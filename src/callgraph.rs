use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::warn;
use serde_json;

use crate::model::Krate;

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
) -> Result<Option<String>> {
    let crate_dir = krate.get_working_dir().await;
    let cargo_toml_path = krate.get_cargo_toml_path().await;
    let target_dir = krate.get_target_dir().await;
    let src_dir = krate.get_src_dir().await;

    tracing::debug!("Run function analysis tool for {}", crate_dir.display());
    // use directory guard to switch and restore directory
    let _dir_guard = DirGuard::new(&crate_dir).map_err(|e| anyhow::anyhow!(e))?;

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

    let mut cmd = Command::new("call-cg4rs");
    cmd.args([
        "--find-callers",
        function_paths,
        "--json-output",
        "--manifest-path",
        &cargo_toml_path.to_string_lossy(),
        "--output-dir",
        &target_dir.to_string_lossy(),
    ]);
    tracing::info!("call-cg4rs command: {:?}", cmd);

    // 设置超时时间为 4 分钟
    let call_cg_result = match timeout(Duration::from_secs(240), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            warn!("call-cg4rs failed: {:?}, skip the crate", e);
            return Ok(None);
        }
        Err(_) => {
            warn!("call-cg4rs analysis timeout (4 minutes), skip the crate");
            return Ok(None);
        }
    };

    if !call_cg_result.status.success() {
        let stderr = String::from_utf8_lossy(&call_cg_result.stderr);
        warn!("call-cg4rs failed: {}, skip the crate", stderr);
        return Ok(None);
    }

    // 新增：查找 caller-*.json 文件
    let mut dir = tokio_fs::read_dir(&target_dir).await?;
    let mut files_vec = Vec::new();
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
            if fname.starts_with("callers-") && fname.ends_with(".json") {
                let content = tokio_fs::read_to_string(&path).await?;
                let content_json: serde_json::Value = serde_json::from_str(&content)
                    .unwrap_or(serde_json::Value::String(content));
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
        if check_src_contain_target_function_single(src, path).await? {
            return Ok(true);
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
                "search process error, exit code: {:?}",
                status.code()
            ));
        }
    }
    Ok(true)
}
