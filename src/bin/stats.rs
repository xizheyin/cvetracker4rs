use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    let cve_id = args.get(1).map(|s| s.as_str()).unwrap_or("CVE-2025-31130");

    let _guard = cross_pro_cg::logger::log_init("logs", cve_id);
    tracing::info!("Running stats-only for {}", cve_id);

    cross_pro_cg::stats::compute_and_write_stats(cve_id).await?;

    tracing::info!("Stats completed for {}", cve_id);
    Ok(())
}
