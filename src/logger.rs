use chrono::Local;
use tracing_log::LogTracer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub fn log_init(
    log_file_dir: &str,
    cve_id: &str,
) -> tracing_appender::non_blocking::WorkerGuard {
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
