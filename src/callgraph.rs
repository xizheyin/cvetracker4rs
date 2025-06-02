use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{info, warn};

// 运行函数调用分析工具
pub(crate) async fn run_function_analysis(
    crate_dir: &PathBuf,
    function_path: &str,
) -> Result<Option<String>> {
    let src_dir = crate_dir.join("src");
    if !check_src_contain_target_function(&src_dir.to_string_lossy(), function_path).await? {
        return Ok(None);
    }

    info!(
        "!!! 检查到目标函数{}，开始运行函数调用分析工具",
        function_path
    );

    let manifest_path = crate_dir.join("Cargo.toml");
    let output_dir = crate_dir.join("target"); // 工具生成在 crate 目录下

    let mut cmd = Command::new("call-cg4rs");
    cmd.args(&[
        "--find-callers",
        function_path,
        "--json-output",
        "--manifest-path",
        &manifest_path.to_string_lossy(),
        "--output-dir",
        &output_dir.to_string_lossy(),
    ]);

    // 设置超时时间为 4 分钟
    let call_cg_result = match timeout(Duration::from_secs(240), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            warn!("call-cg4rs工具执行出错: {}，跳过该crate", e);
            return Ok(None);
        }
        Err(_) => {
            warn!("call-cg4rs工具分析超时(4分钟)，跳过该crate");
            return Ok(None);
        }
    };

    if !call_cg_result.status.success() {
        let stderr = String::from_utf8_lossy(&call_cg_result.stderr);
        warn!("call-cg4rs工具执行失败: {}", stderr);
        return Ok(None);
    }

    // 工具生成的 callers.json 路径
    let callers_json_path = output_dir.join("callers.json");
    if !callers_json_path.exists() {
        info!("未找到callers.json文件，说明没有函数调用");
        return Ok(None);
    }

    // 读取callers.json内容
    let callers_content = tokio_fs::read_to_string(&callers_json_path)
        .await
        .context(format!(
            "读取callers.json文件失败: {}",
            callers_json_path.display()
        ))?;

    Ok(Some(callers_content))
}

pub(crate) async fn check_src_contain_target_function(
    src: &str,
    target_function_path: &str,
) -> Result<bool> {
    let function_name = target_function_path.split("::").last().unwrap();

    // 获取参数并添加到命令字符串
    let args: Vec<String> = vec![
        "-r".to_string(),
        "-n".to_string(),
        "--color=always".to_string(),
        function_name.to_string(),
        src.to_owned(),
    ];
    let mut grep_cmd = Command::new("grep");
    grep_cmd.args(args);
    tracing::info!("执行命令: {:?}", grep_cmd);
    // 调用grep命令执行
    let output = grep_cmd.output().await?;
    // 返回grep的退出状态码
    let status = output.status;
    if status.success() {
        return Ok(true);
    } else {
        // grep没有找到匹配内容时会返回非零状态码，这里特殊处理
        if output.stdout.is_empty() && status.code() == Some(1) {
            return Ok(false);
        } else {
            return Err(anyhow::anyhow!("搜索过程出错，退出码: {:?}", status.code()));
        }
    }
}
