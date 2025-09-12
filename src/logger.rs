use crate::model::Krate;
use std::fs;
use std::path::PathBuf;
use tokio::fs as tokio_fs;
use tracing_log::LogTracer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub struct Logger {
    log_file_dir: String,
}

impl Logger {
    pub fn new(log_file_dir: String) -> Self {
        LogTracer::builder()
            .init()
            .expect("Failed to initialize LogTracer");
        // 确保日志目录存在
        if let Err(e) = fs::create_dir_all(&log_file_dir) {
            eprintln!("Failed to create log directory {}: {}", log_file_dir, e);
        }
        Self { log_file_dir }
    }

    /// log init in logs/YYYY-MM-DD_HH-MM-SS/cve-id.log
    /// YYYY-MM-DD_HH-MM-SS is the timestamp
    /// cve-id is the cve id
    pub fn log_init(
        &self,
        cve_id: &str,
    ) -> (
        tracing_appender::non_blocking::WorkerGuard,
        tracing::dispatcher::DefaultGuard,
    ) {
        // 当环境变量 DISABLE_STDOUT_LOG=1 时，不往控制台输出日志，避免打断进度条
        let use_stdout = std::env::var("DISABLE_STDOUT_LOG")
            .map(|v| v != "1")
            .unwrap_or(true);
        let std_writer = tracing_subscriber::fmt::writer::BoxMakeWriter::new(move || {
            if use_stdout {
                Box::new(std::io::stdout()) as Box<dyn std::io::Write + Send + Sync>
            } else {
                Box::new(std::io::sink()) as Box<dyn std::io::Write + Send + Sync>
            }
        });
        let std_layer = tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_writer(std_writer);

        let file_name = format!("{}.log", cve_id);
        let file_appender = tracing_appender::rolling::never(&self.log_file_dir, file_name);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_writer(non_blocking);

        // 让日志级别由 RUST_LOG 环境变量控制，默认 info
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let collector = tracing_subscriber::registry()
            .with(env_filter)
            .with(std_layer)
            .with(file_layer);

        let _guard = tracing::subscriber::set_default(collector);

        (guard, _guard)
    }
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
