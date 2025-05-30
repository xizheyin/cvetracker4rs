mod database;
mod dependency_analyzer;
mod dir;
mod logger;
mod model;
mod utils;

use dependency_analyzer::DependencyAnalyzer;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cve_id = "CVE-2025-2022";
    let crate_name = "openssl";
    let version_range = ">=0.10.39, <0.10.72";
    let target_function_path = "openssl::cipher::Cipher::fetch";
    let log_file_path = Path::new("logs/cross_pro_cg.log");

    dotenv::dotenv().ok();
    let _guard = logger::log_init();
    if log_file_path.exists() {
        fs::remove_file(log_file_path)?;
    }

    tracing::info!("开始分析依赖关系");
    let analyzer = DependencyAnalyzer::new().await?;
    analyzer
        .analyze(cve_id, crate_name, version_range, target_function_path)
        .await?;

    tracing::info!("分析完成");
    Ok(())
}
