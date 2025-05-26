use tracing_log::LogTracer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

pub(crate) fn log_init() -> tracing_appender::non_blocking::WorkerGuard {
    LogTracer::builder()
        .init()
        .expect("Failed to initialize LogTracer");

    let std_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(std::io::stdout)
        .with_filter(LevelFilter::INFO);

    let file_appender = tracing_appender::rolling::daily("logs", "cross_pro_cg.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_writer(non_blocking)
        .with_filter(LevelFilter::INFO);

    let collector = tracing_subscriber::registry()
        .with(std_layer)
        .with(file_layer);

    tracing::subscriber::set_global_default(collector).expect("Failed to set subscriber");

    guard
}
