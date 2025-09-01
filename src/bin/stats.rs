use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    let cve_id = args.get(1).map(|s| s.as_str()).unwrap_or("CVE-2025-31130");

    let _guard = libcvetracker::logger::log_init("logs", cve_id);
    tracing::info!("Running stats-only for {}", cve_id);

    //libcvetracker::stats::compute_and_write_stats(cve_id).await?;

    // Compute enhanced stats for academic research
    tracing::info!("Computing enhanced statistics for academic analysis...");
    libcvetracker::enhanced_stats::compute_enhanced_stats(cve_id).await?;
    
    // Generate academic report for paper writing
    tracing::info!("Generating academic research report...");
    libcvetracker::academic_report::generate_academic_report(cve_id).await?;

    tracing::info!("Stats completed for {}", cve_id);
    Ok(())
}
