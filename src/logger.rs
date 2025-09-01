use crate::model::Krate;
use chrono::Local;
use std::path::PathBuf;
use tokio::fs as tokio_fs;
use tracing_log::LogTracer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub fn log_init(log_file_dir: &str, cve_id: &str) -> tracing_appender::non_blocking::WorkerGuard {
    LogTracer::builder()
        .init()
        .expect("Failed to initialize LogTracer");

    // 让日志级别由 RUST_LOG 环境变量控制，默认 info
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let std_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(std::io::stdout);

    // 生成带日期的文件名
    let now = Local::now();
    let file_name = format!("{}_{}.log", now.format("%Y-%m-%d_%H-%M-%S"), cve_id);
    let file_appender = tracing_appender::rolling::never(log_file_dir, file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(non_blocking);

    let collector = tracing_subscriber::registry()
        .with(env_filter)
        .with(std_layer)
        .with(file_layer);

    tracing::subscriber::set_global_default(collector).expect("Failed to set subscriber");

    guard
}

/// create log file for each process, and return the log file and error log file
/// log file name: logs_cg4rs/{cve_id}_{timestamp}/cg4rs_{krate_name}_{krate_version}.log
/// error log file name: logs_cg4rs/{cve_id}_{timestamp}/cg4rs_{krate_name}_{krate_version}_error.log
pub async fn create_log_file(
    logs_dir: &PathBuf,
    krate: &Krate,
) -> anyhow::Result<(std::fs::File, std::fs::File)> {
    // 创建日志目录（使用绝对路径）
    tokio_fs::create_dir_all(&logs_dir).await?;

    let logs_file_name_suffix = format!("{}_{}", krate.name, krate.version);
    let logs_filepath = logs_dir.join(format!("cg4rs_{}.log", logs_file_name_suffix));

    let error_output_filepath = logs_dir.join(format!("cg4rs_{}_error.log", logs_file_name_suffix));

    // 创建日志文件 - 使用 std::fs::File 而不是 tokio::fs::File
    let log_file = std::fs::File::create(&logs_filepath)?;
    let error_output_file = std::fs::File::create(&error_output_filepath)?;

    Ok((log_file, error_output_file))
}
