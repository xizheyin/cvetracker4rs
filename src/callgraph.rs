use crate::model::Krate;
use crate::process::graceful_kill_process;
use anyhow::Result;

use serde_json;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::{self as tokio_fs, read_dir};
use tokio::process::Command;
use tokio::time::sleep;
use tracing::warn;

/// Directory guard
/// when running the function analysis tool, the current directory will be changed to the working directory of the crate
/// so we need to restore the original directory after the function analysis tool is finished
struct DirGuard {
    original: PathBuf,
}

impl DirGuard {
    fn new(new_dir: &PathBuf) -> std::io::Result<Self> {
        let original = env::current_dir()?;
        env::set_current_dir(new_dir)?;
        Ok(DirGuard { original })
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.original);
    }
}

// run function analysis tool
pub(crate) async fn run_function_analysis(
    krate: &Krate,
    function_paths: &str,
    logs_dir: &PathBuf,
) -> Result<Option<String>> {
    let crate_dir = krate.get_working_src_code_dir().await;
    let cargo_toml_path = krate.get_cargo_toml_path().await;
    let target_dir = krate.get_target_dir().await;
    let src_dir = krate.get_src_dir().await;

    tracing::debug!("Run function analysis tool for {}", crate_dir.display());
    // use directory guard to switch and restore directory
    let _dir_guard = DirGuard::new(&crate_dir)
        .map_err(|e| anyhow::anyhow!(e))
        .unwrap();

    // check if the src directory contains the target function by grep

    if !check_src_contain_target_function(&src_dir.to_string_lossy(), function_paths).await? {
        tracing::info!(
            "Skip the function analysis, because {} does not contain the target function {}",
            src_dir.display(),
            function_paths
        );
        return Ok(None);
    }

    tracing::info!(
        "detect target function: {} in {}",
        function_paths,
        src_dir.display()
    );

    let (log_file, error_output_file) = crate::logger::create_log_file(&logs_dir, krate)
        .await
        .unwrap();

    let mut child = Command::new("call-cg4rs")
        .env("RUST_LOG", "info")
        .args([
            "--find-callers",
            function_paths,
            "--json-output",
            "--manifest-path",
            &cargo_toml_path.to_string_lossy(),
            "--output-dir",
            &target_dir.to_string_lossy(),
        ])
        .stdout(log_file)
        .stderr(error_output_file)
        .spawn()
        .unwrap();

    let exit = tokio::select! {
        exit = child.wait() => {
            exit.map_err(|e| anyhow::anyhow!(e))
        }
        _ = sleep(Duration::from_secs(240)) => {
            warn!("call-cg4rs analysis timeout (4 minutes), attempting graceful shutdown");
            // 使用优雅终止：先 SIGTERM，10秒后如果还没退出则 SIGKILL
            let _ = graceful_kill_process(&mut child, 10).await;
            Err(anyhow::anyhow!("call-cg4rs analysis timeout (4 minutes), process terminated"))
        }
    };

    match exit {
        Ok(exit) => {
            if !exit.success() {
                warn!(
                    "call-cg4rs failed for {}: {:?}, check logs in logs directory",
                    krate.name, exit
                );
                return Ok(None);
            }
        }
        Err(e) => {
            warn!(
                "call-cg4rs failed for {}: {:?}, check logs in logs directory",
                krate.name, e
            );
            return Ok(None);
        }
    }

    // Find caller-*.json files
    // If the target directory does not exist, it's ok
    // because the call-cg4rs may have skipped analyzing it
    let mut dir = match tokio_fs::read_dir(&target_dir).await {
        Ok(dir) => dir,
        Err(e) => {
            if read_dir(&crate_dir).await.is_err() {
                warn!("{}: crate {} does not exist", e, crate_dir.display());
                return Ok(None);
            }
            warn!("{}: target dir{} does not exist", e, target_dir.display());
            return Ok(None);
        }
    };
    let mut files_vec = Vec::new();
    while let Some(entry) = dir.next_entry().await.expect(&format!(
        "Failed to read directory entry: {}",
        target_dir.display()
    )) {
        let path = entry.path();
        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
            if fname.starts_with("callers-") && fname.ends_with(".json") {
                let content = tokio_fs::read_to_string(&path)
                    .await
                    .expect(&format!("Failed to read file: {}", path.display()));
                let content_json: serde_json::Value =
                    serde_json::from_str(&content).unwrap_or(serde_json::Value::String(content));
                let json_obj = serde_json::json!({
                    "file": fname,
                    "file-content": content_json
                });
                files_vec.push(json_obj);
            }
        }
    }
    if files_vec.is_empty() {
        warn!(
            "caller(s)-*.json file not found in {}, skip the crate",
            target_dir.display()
        );
        return Ok(None);
    }
    let callers_content = serde_json::to_string_pretty(&files_vec)?;
    Ok(Some(callers_content))
}

pub(crate) async fn check_src_contain_target_function(
    src: &str,
    target_function_paths: &str,
) -> Result<bool> {
    for path in target_function_paths.split(',') {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        match check_src_contain_target_function_single(src, path).await {
            Ok(true) => return Ok(true),
            Ok(false) => continue,
            Err(e) => {
                warn!(
                    "check_src_contain_target_function_single failed for {}: {}",
                    path, e
                );
                return Err(e);
            }
        }
    }
    Ok(false)
}

async fn check_src_contain_target_function_single(
    src: &str,
    target_function_path: &str,
) -> Result<bool> {
    let function_name = target_function_path.split("::").last().unwrap();

    let args: Vec<String> = vec![
        "-r".to_string(),
        "-n".to_string(),
        "--color=always".to_string(),
        function_name.to_string(),
        src.to_owned(),
    ];
    let mut grep_cmd = Command::new("grep");
    grep_cmd.args(args);
    let output = grep_cmd.output().await?;
    let status = output.status;
    if !status.success() {
        if output.stdout.is_empty() && status.code() == Some(1) {
            return Ok(false);
        } else {
            return Err(anyhow::anyhow!(
                "search process error in {}, exit code: {:?}",
                src,
                status.code()
            ));
        }
    }
    Ok(true)
}
