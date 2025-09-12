use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use libcvetracker::dependency_analyzer::DependencyAnalyzer;
use libcvetracker::logger;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args: Vec<String> = env::args().collect();

    let cve_id = args.get(1).map(|s| s.as_str()).unwrap_or("CVE-2025-31130");
    let crate_name = args.get(2).map(|s| s.as_str()).unwrap_or("gix-features");
    let version_range = args.get(3).map(|s| s.as_str()).unwrap_or("<0.41.0");
    let target_function_paths = args.get(4).map(|s| s.as_str()).unwrap_or(
        "gix_features::hash::Hasher::digest,gix_features::hash::Hasher::update,gix_features::hash::Write::flush,gix_features::hash::Write::new,gix_features::hash::Write::write,gix_features::hash::bytes,gix_features::hash::bytes_of_filegix_features::hash::bytes_with_hasher,gix_features::hash::hasher",
    );

    let log_dir = std::env::var("LOG_DIR").expect("LOG_DIR is not set");
    let _guard = logger::Logger::new(log_dir).log_init(cve_id);

    tracing::info!("Start to run the dependency analyzer\ncve_id: {}\ncrate_name: {}\nversion_range: {}\ntarget_function_path: {}\n", cve_id, crate_name, version_range, target_function_paths);

    // spinner for overall progress (固定在终端底部，绘制到 stderr)
    let mp = MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(10));
    let spinner = mp.add(ProgressBar::new_spinner());
    spinner.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap()
            .tick_chars("|/-\\"),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_message("初始化分析器...");
    let analyzer = DependencyAnalyzer::new(cve_id).await?;
    spinner.set_message("开始依赖分析...");
    analyzer
        .analyze(crate_name, version_range, target_function_paths)
        .await?;

    spinner.set_message("计算统计信息...");

    // // After analysis, compute aggregated stats for the CVE
    libcvetracker::stats::compute_and_write_stats(cve_id).await?;

    spinner.finish_with_message("分析完成");

    tracing::info!("Dependency analyzer finished successfully");
    Ok(())
}
