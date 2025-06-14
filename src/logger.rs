use tracing_log::LogTracer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub(crate) fn log_init() -> tracing_appender::non_blocking::WorkerGuard {
    LogTracer::builder()
        .init()
        .expect("Failed to initialize LogTracer");

    // 让日志级别由 RUST_LOG 环境变量控制，默认 info
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let std_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(std::io::stdout);

    let file_appender = tracing_appender::rolling::daily("logs", "cross_pro_cg.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(non_blocking);

    let collector = tracing_subscriber::registry()
        .with(env_filter) // 关键：加上 env_filter
        .with(std_layer)
        .with(file_layer);

    tracing::subscriber::set_global_default(collector).expect("Failed to set subscriber");

    guard
}