use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use tokio::fs as tokio_fs;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FunctionStats {
    pub function_file: String,
    pub total_callers: usize,
    pub unique_call_paths: usize,
    pub unique_path_hashes: usize,
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
    pub functions: BTreeMap<String, FunctionStats>,
    pub subjects: Vec<SubjectStats>,
    /// Top subjects by callers
    pub top_subjects_by_callers: Vec<(String, usize)>,
}

fn analysis_results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analysis_results")
}

fn strip_cve_suffix(filename: &str, cve_id: &str) -> Option<String> {
    let suffix = format!("-{}.txt", cve_id);
    if let Some(stripped) = filename.strip_suffix(&suffix) {
        return Some(stripped.to_string());
    }
    None
}

fn function_from_file_key(file_key: &str) -> String {
    // Expected like: callers-gix_features::hash::hasher.json
    file_key
        .strip_prefix("callers-")
        .and_then(|s| s.strip_suffix(".json"))
        .unwrap_or(file_key)
        .to_string()
}

pub async fn compute_and_write_stats(cve_id: &str) -> Result<()> {
    let dir = analysis_results_dir();
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
    let mut function_unique_hashes: HashMap<String, BTreeSet<String>> = HashMap::new();

    // subject aggregations
    let mut subjects_map: BTreeMap<String, SubjectStats> = BTreeMap::new();

    while let Some(entry) = dir_entries.next_entry().await? {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let fname = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(subject) = strip_cve_suffix(fname, cve_id) else {
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
            .entry(subject.clone())
            .or_insert_with(|| SubjectStats {
                subject: subject.clone(),
                ..Default::default()
            });

        global.total_subjects += 1;

        for file_obj in json.as_array().unwrap() {
            global.total_function_result_files += 1;
            let file_key = file_obj.get("file").and_then(|v| v.as_str()).unwrap_or("");
            let func_key = function_from_file_key(file_key);

            let file_content = file_obj.get("file-content");
            let Some(file_content) = file_content else {
                continue;
            };
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
            let uniq_hashes = function_unique_hashes
                .entry(func_key.clone())
                .or_insert_with(BTreeSet::new);

            for caller in callers {
                if let Some(path) = caller.get("path").and_then(|v| v.as_str()) {
                    uniq_paths.insert(path.to_string());
                }
                if let Some(hash) = caller.get("path_hash").and_then(|v| v.as_str()) {
                    uniq_hashes.insert(hash.to_string());
                }
                if let Some(pc) = caller.get("path_constraints").and_then(|v| v.as_i64()) {
                    let entry = global.path_constraints_histogram.entry(pc).or_insert(0);
                    *entry += 1;
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
        let unique_hashes = function_unique_hashes
            .get(&func_key)
            .map(|s| s.len())
            .unwrap_or(0);

        global.functions.insert(
            func_key.clone(),
            FunctionStats {
                function_file: func_key,
                total_callers,
                unique_call_paths: unique_paths,
                unique_path_hashes: unique_hashes,
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
        md.push_str(&format!(
            "- {}: callers={}, unique_paths={}, unique_hashes={}\n",
            func, fs.total_callers, fs.unique_call_paths, fs.unique_path_hashes
        ));
    }
    md.push_str("\n## Path constraints histogram\n\n");
    for (k, v) in &global.path_constraints_histogram {
        md.push_str(&format!("- {}: {}\n", k, v));
    }
    let out_md_path = dir.join(format!("stats-{}.md", cve_id));
    tokio_fs::write(&out_md_path, md).await?;

    tracing::info!("stats written: {:?}, {:?}", out_json_path, out_md_path);
    Ok(())
}
