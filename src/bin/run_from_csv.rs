use std::env;
use std::fs::File;
use std::io::Read;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, serde::Deserialize)]
struct Row {
    cve_id: String,
    crate_name: String,
    version_range: String,
    target_function_paths: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    let csv_path = args
        .get(1)
        .map(|s| s.as_str())
        .ok_or("用法: run_from_csv <csv_path> [--has-header=true|false]")?;

    let has_header = args
        .iter()
        .find(|s| s.starts_with("--has-header="))
        .map(|s| s.trim_start_matches("--has-header=").parse::<bool>().unwrap_or(true))
        .unwrap_or(true);

    let mut rdr_builder = csv::ReaderBuilder::new();
    rdr_builder.has_headers(has_header);

    let mut file = File::open(csv_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let mut rdr = rdr_builder.from_reader(content.as_bytes());

    // 预读取以统计总行数
    let mut rows: Vec<Row> = Vec::new();
    for result in rdr.deserialize::<Row>() {
        rows.push(result?);
    }

    let total = rows.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} {percent}% {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for (idx, row) in rows.into_iter().enumerate() {
        pb.set_message(format!(
            "处理: {} {} {}",
            row.cve_id, row.crate_name, row.version_range
        ));
        pb.inc(1);

        let _guard = libcvetracker::logger::log_init("logs", &row.cve_id);
        tracing::info!(
            "Start to run the dependency analyzer\ncve_id: {}\ncrate_name: {}\nversion_range: {}\ntarget_function_path: {}\n",
            row.cve_id, row.crate_name, row.version_range, row.target_function_paths
        );

        let analyzer = libcvetracker::dependency_analyzer::DependencyAnalyzer::new(&row.cve_id)
            .await?;
        analyzer
            .analyze(
                &row.crate_name,
                &row.version_range,
                &row.target_function_paths,
            )
            .await?;

        libcvetracker::stats::compute_and_write_stats(&row.cve_id).await?;

        // 每个任务结束后给出完成提示
        pb.set_message(format!(
            "完成: {} ({}/{})",
            row.cve_id,
            idx + 1,
            total
        ));
    }
    pb.finish_with_message("全部完成");

    Ok(())
}


