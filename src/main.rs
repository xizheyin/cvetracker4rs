mod callgraph;
mod database;
mod dependency_analyzer;
mod dir;
mod logger;
mod model;
mod utils;

use dependency_analyzer::DependencyAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cve_id = "CVE-2025-31130";
    let crate_name = "gix-features";
    let version_range = "<0.41.0";
    let target_function_paths = "gix_features::hash::Hasher::digest,gix_features::hash::Hasher::update,gix_features::hash::Write::flush,gix_features::hash::Write::new,gix_features::hash::Write::write,gix_features::hash::bytes,gix_features::hash::bytes_of_file,gix_features::hash::bytes_with_hasher,gix_features::hash::hasher";

    dotenv::dotenv().ok();
    let _guard = logger::log_init("logs", cve_id);

    tracing::info!("Start to run the dependency analyzer\ncve_id: {}\ncrate_name: {}\nversion_range: {}\ntarget_function_path: {}\n", cve_id, crate_name, version_range, target_function_paths);
    let analyzer = DependencyAnalyzer::new(cve_id).await?;
    analyzer
        .analyze(crate_name, version_range, target_function_paths)
        .await?;

    tracing::info!("Dependency analyzer finished successfully");
    Ok(())
}
