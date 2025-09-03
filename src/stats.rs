
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use tokio::fs as tokio_fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerSample {
    pub subject: String,
    pub caller_path: String,
    pub path_constraints: i64,
    pub path_package_num: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FunctionStats {
    pub function_file: String,
    pub total_callers: usize,
    pub unique_call_paths: usize,
    pub path_constraints_min: Option<i64>,
    pub path_constraints_max: Option<i64>,
    pub path_constraints_avg: f64,
    pub path_constraints_p50: Option<f64>,
    pub path_constraints_p90: Option<f64>,
    pub path_constraints_p95: Option<f64>,
    pub path_constraints_p99: Option<f64>,
    pub package_hops_min: Option<i64>,
    pub package_hops_max: Option<i64>,
    pub package_hops_avg: Option<f64>,
    pub package_hops_p50: Option<f64>,
    pub package_hops_p90: Option<f64>,
    pub package_hops_p95: Option<f64>,
    pub package_hops_p99: Option<f64>,
    pub path_constraints_histogram: BTreeMap<i64, usize>,
    pub package_hops_histogram: BTreeMap<i64, usize>,
    pub top_callers_by_constraints: Vec<CallerSample>,
    pub top_callers_by_package_hops: Vec<CallerSample>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SubjectStats {
    /// e.g., "cargo-audit-0.21.2" (filename without -CVE.txt)
    pub subject: String,
    pub total_callers: usize,
    pub per_function_callers: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlobalStats {
    pub cve_id: String,
    pub total_subjects: usize,
    pub total_function_result_files: usize,
    pub total_callers: usize,
    pub path_constraints_histogram: BTreeMap<i64, usize>,
    pub package_hops_histogram: BTreeMap<i64, usize>,
    pub functions: BTreeMap<String, FunctionStats>,
    pub subjects: Vec<SubjectStats>,
    /// Top subjects by callers
    pub top_subjects_by_callers: Vec<(String, usize)>,
}

fn analysis_results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analysis_results")
}

fn function_from_file_key(file_key: &str) -> String {
    file_key
        .strip_prefix("callers-")
        .and_then(|s| s.strip_suffix(".json"))
        .unwrap_or(file_key)
        .to_string()
}


pub async fn compute_and_write_stats(cve_id: &str) -> Result<()> {
    let dir = analysis_results_dir().join(cve_id);
    if !dir.exists() {
        tracing::info!("analysis_results not found, skip stats");
        return Ok(());
    }

    let mut dir_entries = tokio_fs::read_dir(&dir).await?;

    let mut global = GlobalStats {
        cve_id: cve_id.to_string(),
        ..Default::default()
    };

    // function aggregations
    let mut function_total_callers: HashMap<String, usize> = HashMap::new();
    let mut function_unique_paths: HashMap<String, BTreeSet<String>> = HashMap::new();

    let mut function_path_constraints_values: HashMap<String, Vec<i64>> = HashMap::new();
    let mut function_package_hops_values: HashMap<String, Vec<i64>> = HashMap::new();
    let mut function_path_constraints_hist: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();
    let mut function_package_hops_hist: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();
    let mut function_top_constraints_samples: HashMap<String, Vec<CallerSample>> = HashMap::new();
    let mut function_top_pkg_samples: HashMap<String, Vec<CallerSample>> = HashMap::new();

    // subject aggregations
    let mut subjects_map: BTreeMap<String, SubjectStats> = BTreeMap::new();

    while let Some(entry) = dir_entries.next_entry().await? {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // crate name - version.txt
        let cnv = if let Some(s) = path.file_name().and_then(|s| s.to_str())
            && let Some(s) = s.strip_suffix(".txt")
        {
            s.to_string()
        } else {
            continue;
        };

        let content = match tokio_fs::read_to_string(&path).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to read {:?}: {}", path, e);
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to parse JSON in {:?}: {}", path, e);
                continue;
            }
        };

        if !json.is_array() {
            continue;
        }

        let subject_entry = subjects_map
            .entry(cnv.clone())
            .or_insert_with(|| SubjectStats {
                subject: cnv.clone(),
                ..Default::default()
            });

        global.total_subjects += 1;

        // 当前结构：每个文件对象包含 file 与 file-content，后者含 target 与 callers[]
        for file_obj in json.as_array().unwrap() {
            global.total_function_result_files += 1;
            let file_key = file_obj.get("file").and_then(|v| v.as_str()).unwrap_or("");
            let file_content = match file_obj.get("file-content") {
                Some(v) => v,
                None => continue,
            };

            let func_key = file_content
                .get("target")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| function_from_file_key(file_key));

            let callers = file_content
                .get("callers")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let per_func_counter = subject_entry
                .per_function_callers
                .entry(func_key.clone())
                .or_insert(0);
            *per_func_counter += callers.len();

            subject_entry.total_callers += callers.len();
            global.total_callers += callers.len();

            let total = function_total_callers.entry(func_key.clone()).or_insert(0);
            *total += callers.len();

            let uniq_paths = function_unique_paths
                .entry(func_key.clone())
                .or_insert_with(BTreeSet::new);

            for caller in callers {
                if let Some(path) = caller.get("path").and_then(|v| v.as_str()) {
                    uniq_paths.insert(path.to_string());
                }
                if let Some(pc) = caller.get("path_constraints").and_then(|v| v.as_i64()) {
                    // per-target histogram
                    let entry = function_path_constraints_hist
                        .entry(func_key.clone())
                        .or_insert_with(BTreeMap::new)
                        .entry(pc)
                        .or_insert(0);
                    *entry += 1;
                    // global histogram
                    let entry = global.path_constraints_histogram.entry(pc).or_insert(0);
                    *entry += 1;
                    function_path_constraints_values
                        .entry(func_key.clone())
                        .or_insert_with(Vec::new)
                        .push(pc);
                    // sample list for top by constraints
                    if let Some(caller_path) = caller.get("path").and_then(|v| v.as_str()) {
                        let sample = CallerSample {
                            subject: cnv.clone(),
                            caller_path: caller_path.to_string(),
                            path_constraints: pc,
                            path_package_num: caller.get("path_package_num").and_then(|v| v.as_i64()),
                        };
                        function_top_constraints_samples
                            .entry(func_key.clone())
                            .or_insert_with(Vec::new)
                            .push(sample);
                    }
                }
                if let Some(pkg) = caller.get("path_package_num").and_then(|v| v.as_i64()) {
                    let entry = function_package_hops_hist
                        .entry(func_key.clone())
                        .or_insert_with(BTreeMap::new)
                        .entry(pkg)
                        .or_insert(0);
                    *entry += 1;
                    let entry = global.package_hops_histogram.entry(pkg).or_insert(0);
                    *entry += 1;
                    function_package_hops_values
                        .entry(func_key.clone())
                        .or_insert_with(Vec::new)
                        .push(pkg);
                    if let Some(caller_path) = caller.get("path").and_then(|v| v.as_str()) {
                        let sample = CallerSample {
                            subject: cnv.clone(),
                            caller_path: caller_path.to_string(),
                            path_constraints: caller
                                .get("path_constraints")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0),
                            path_package_num: Some(pkg),
                        };
                        function_top_pkg_samples
                            .entry(func_key.clone())
                            .or_insert_with(Vec::new)
                            .push(sample);
                    }
                }
            }
        }
    }

    // finalize function stats
    for (func_key, total_callers) in function_total_callers {
        let unique_paths = function_unique_paths
            .get(&func_key)
            .map(|s| s.len())
            .unwrap_or(0);

        // path constraints stats
        let (pc_min, pc_max, pc_avg) =
            if let Some(vals) = function_path_constraints_values.get(&func_key) {
                if vals.is_empty() {
                    (None, None, 0.0)
                } else {
                    let min_v = *vals.iter().min().unwrap();
                    let max_v = *vals.iter().max().unwrap();
                    let sum: i64 = vals.iter().sum();
                    let avg = sum as f64 / vals.len() as f64;
                    (Some(min_v), Some(max_v), avg)
                }
            } else {
                (None, None, 0.0)
            };

        let pc_percentiles = |vals: &Vec<i64>| -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
            if vals.is_empty() { return (None, None, None, None); }
            let mut v = vals.clone();
            v.sort_unstable();
            let nth = |p: f64| -> f64 {
                let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
                v[idx] as f64
            };
            (Some(nth(0.50)), Some(nth(0.90)), Some(nth(0.95)), Some(nth(0.99)))
        };
        let (pc_p50, pc_p90, pc_p95, pc_p99) = function_path_constraints_values
            .get(&func_key)
            .map(pc_percentiles)
            .unwrap_or((None, None, None, None));

        // package hops stats
        let (pkg_min, pkg_max, pkg_avg_opt) =
            if let Some(vals) = function_package_hops_values.get(&func_key) {
                if vals.is_empty() {
                    (None, None, None)
                } else {
                    let min_v = *vals.iter().min().unwrap();
                    let max_v = *vals.iter().max().unwrap();
                    let sum: i64 = vals.iter().sum();
                    let avg = sum as f64 / vals.len() as f64;
                    (Some(min_v), Some(max_v), Some(avg))
                }
            } else {
                (None, None, None)
            };

        let pkg_percentiles = |vals: &Vec<i64>| -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
            if vals.is_empty() { return (None, None, None, None); }
            let mut v = vals.clone();
            v.sort_unstable();
            let nth = |p: f64| -> f64 {
                let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
                v[idx] as f64
            };
            (Some(nth(0.50)), Some(nth(0.90)), Some(nth(0.95)), Some(nth(0.99)))
        };
        let (pkg_p50, pkg_p90, pkg_p95, pkg_p99) = function_package_hops_values
            .get(&func_key)
            .map(pkg_percentiles)
            .unwrap_or((None, None, None, None));

        // Top-N 样本（约束与包跳数各取前 10）
        let mut top_constraints = function_top_constraints_samples
            .get(&func_key)
            .cloned()
            .unwrap_or_default();
        top_constraints.sort_by(|a, b| b.path_constraints.cmp(&a.path_constraints));
        top_constraints.truncate(10);

        let mut top_pkg = function_top_pkg_samples
            .get(&func_key)
            .cloned()
            .unwrap_or_default();
        top_pkg.sort_by(|a, b| b.path_package_num.cmp(&a.path_package_num));
        top_pkg.truncate(10);

        global.functions.insert(
            func_key.clone(),
            FunctionStats {
                function_file: func_key.clone(),
                total_callers,
                unique_call_paths: unique_paths,

                path_constraints_min: pc_min,
                path_constraints_max: pc_max,
                path_constraints_avg: pc_avg,
                path_constraints_p50: pc_p50,
                path_constraints_p90: pc_p90,
                path_constraints_p95: pc_p95,
                path_constraints_p99: pc_p99,
                package_hops_min: pkg_min,
                package_hops_max: pkg_max,
                package_hops_avg: pkg_avg_opt,
                package_hops_p50: pkg_p50,
                package_hops_p90: pkg_p90,
                package_hops_p95: pkg_p95,
                package_hops_p99: pkg_p99,
                path_constraints_histogram: function_path_constraints_hist
                    .remove(&func_key)
                    .unwrap_or_default(),
                package_hops_histogram: function_package_hops_hist
                    .remove(&func_key)
                    .unwrap_or_default(),
                top_callers_by_constraints: top_constraints,
                top_callers_by_package_hops: top_pkg,
            },
        );
    }

    // subjects list and top N
    let mut subjects_vec: Vec<SubjectStats> = subjects_map.into_values().collect();
    subjects_vec.sort_by(|a, b| b.total_callers.cmp(&a.total_callers));
    let top_subjects_by_callers: Vec<(String, usize)> = subjects_vec
        .iter()
        .take(20)
        .map(|s| (s.subject.clone(), s.total_callers))
        .collect();
    global.top_subjects_by_callers = top_subjects_by_callers;
    global.subjects = subjects_vec;

    // write out
    let out_json = serde_json::to_string_pretty(&global)?;
    let out_json_path = dir.join(format!("stats-{}.json", cve_id));
    tokio_fs::write(&out_json_path, out_json).await?;

    // A compact markdown for human reading
    let mut md = String::new();
    md.push_str(&format!("# Stats for {}\n\n", cve_id));
    md.push_str(&format!("- Total subjects: {}\n", global.total_subjects));
    md.push_str(&format!(
        "- Total function files: {}\n",
        global.total_function_result_files
    ));
    md.push_str(&format!("- Total callers: {}\n", global.total_callers));
    md.push_str("\n## Top subjects by callers\n\n");
    for (name, cnt) in &global.top_subjects_by_callers {
        md.push_str(&format!("- {}: {}\n", name, cnt));
    }
    md.push_str("\n## Functions summary\n\n");
    for (func, fs) in &global.functions {
        let pkg_stats = match (
            fs.package_hops_min,
            fs.package_hops_max,
            fs.package_hops_avg,
        ) {
            (Some(a), Some(b), Some(c)) => format!("{}/{}/{:.2}", a, b, c),
            _ => "-".to_string(),
        };
        md.push_str(&format!(
            "- {}: callers={}, unique_paths={}, pc(min/max/avg/p50/p90/p95/p99)={:?}/{:?}/{:.2}/{:?}/{:?}/{:?}/{:?}, pkg(min/max/avg/p50/p90/p95/p99)={}/{:?}/{:?}/{:?}/{:?}\n",
            func,
            fs.total_callers,
            fs.unique_call_paths,
            fs.path_constraints_min,
            fs.path_constraints_max,
            fs.path_constraints_avg,
            fs.path_constraints_p50,
            fs.path_constraints_p90,
            fs.path_constraints_p95,
            fs.path_constraints_p99,
            pkg_stats,
            fs.package_hops_p50,
            fs.package_hops_p90,
            fs.package_hops_p95,
            fs.package_hops_p99
        ));

        if !fs.path_constraints_histogram.is_empty() {
            md.push_str("  - path_constraints histogram:\n");
            for (k, v) in &fs.path_constraints_histogram {
                md.push_str(&format!("    - {}: {}\n", k, v));
            }
        }
        if !fs.package_hops_histogram.is_empty() {
            md.push_str("  - package_hops histogram:\n");
            for (k, v) in &fs.package_hops_histogram {
                md.push_str(&format!("    - {}: {}\n", k, v));
            }
        }

        if !fs.top_callers_by_constraints.is_empty() {
            md.push_str("  - Top callers by constraints (max 10):\n");
            for s in &fs.top_callers_by_constraints {
                md.push_str(&format!(
                    "    - [{}] {} (pc={}, pkg={:?})\n",
                    s.subject, s.caller_path, s.path_constraints, s.path_package_num
                ));
            }
        }
        if !fs.top_callers_by_package_hops.is_empty() {
            md.push_str("  - Top callers by package hops (max 10):\n");
            for s in &fs.top_callers_by_package_hops {
                md.push_str(&format!(
                    "    - [{}] {} (pc={}, pkg={:?})\n",
                    s.subject, s.caller_path, s.path_constraints, s.path_package_num
                ));
            }
        }
    }
    md.push_str("\n## Path constraints histogram\n\n");
    for (k, v) in &global.path_constraints_histogram {
        md.push_str(&format!("- {}: {}\n", k, v));
    }
    if !global.package_hops_histogram.is_empty() {
        md.push_str("\n## Package hops (package_num) histogram\n\n");
        for (k, v) in &global.package_hops_histogram {
            md.push_str(&format!("- {}: {}\n", k, v));
        }
    }
    let out_md_path = dir.join(format!("stats-{}.md", cve_id));
    tokio_fs::write(&out_md_path, md).await?;

    tracing::info!("stats written: {:?}, {:?}", out_json_path, out_md_path);
    Ok(())
}
