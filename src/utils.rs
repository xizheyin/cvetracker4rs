use anyhow::Context;
use futures::stream::{self as futures_stream, StreamExt};
use semver::{Version, VersionReq};
use std::{collections::VecDeque, path::Path};
use tokio::fs as tokio_fs;
use tokio::process::Command;
use toml_edit::DocumentMut;

use crate::{
    database::Database,
    model::{Krate, ReverseDependency},
};

/// Get reverse dependencies for a krate in range of its version
/// every reverse dependency will yield two versions,
/// one is the oldest version and the other is the newest version
pub(crate) async fn get_reverse_deps_for_krate(
    database: &Database,
    krate: &Krate,
) -> anyhow::Result<Vec<ReverseDependency>> {
    let precise_version = &krate.version;

    let reverse_deps = database.query_dependents(&krate.name).await?;
    let reverse_deps_for_certain_version =
        filter_dependents_by_version_req(reverse_deps, precise_version).await?;

    let mut dependents_map: std::collections::HashMap<String, Vec<ReverseDependency>> =
        std::collections::HashMap::new();

    for revdep in reverse_deps_for_certain_version {
        dependents_map
            .entry(revdep.name.clone())
            .or_default()
            .push(revdep.clone());
    }

    let mut selected_dependents = futures_stream::iter(dependents_map.iter_mut())
        .then(|(_, revdeps)| async move {
            select_two_end_vers(
                revdeps
                    .iter()
                    .map(|revdep| revdep.version.clone())
                    .collect(),
                ">=0.0.0",
            )
            .await
            .into_iter()
            .map(|(idx, _)| revdeps[idx].clone())
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    selected_dependents.sort();
    Ok(selected_dependents)
}

pub(crate) async fn filter_dependents_by_version_req(
    dependents: Vec<ReverseDependency>,
    precise_version: &str,
) -> anyhow::Result<Vec<ReverseDependency>> {
    let precise_version = semver::Version::parse(precise_version)?;
    Ok(dependents
        .into_iter()
        .filter(|dep| {
            semver::VersionReq::parse(dep.req.as_str())
                .map(|req| req.matches(&precise_version))
                .unwrap_or(false)
        })
        .collect())
}

pub(crate) async fn select_two_end_vers(
    versions: Vec<String>,
    version_range: &str,
) -> Vec<(usize, semver::Version)> {
    let filtered_versions = filter_versions_by_version_range(versions, version_range).await;
    let (oldest_version, newest_version) =
        select_oldest_and_newest_versions(filtered_versions).await;
    vec![oldest_version, newest_version]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
}

async fn filter_versions_by_version_range(
    versions: Vec<String>,
    version_range: &str,
) -> Vec<semver::Version> {
    let version_req = VersionReq::parse(version_range).unwrap();
    versions
        .into_iter()
        .filter_map(|version| {
            let parsed_version = Version::parse(&version).ok()?;
            version_req
                .matches(&parsed_version)
                .then_some(parsed_version)
        })
        .collect::<Vec<_>>()
}

async fn select_oldest_and_newest_versions(
    versions: Vec<semver::Version>,
) -> (
    Option<(usize, semver::Version)>,
    Option<(usize, semver::Version)>,
) {
    if versions.is_empty() {
        return (None, None);
    }
    let mut versions_with_index = versions.into_iter().enumerate().collect::<Vec<_>>();

    versions_with_index.sort_by(|a, b| a.1.cmp(&b.1));

    let mut result = (None, None);

    if let Some(oldest) = versions_with_index.first() {
        result.0 = Some(oldest.clone());
    }

    if versions_with_index.len() > 1 {
        if let Some(newest) = versions_with_index.last() {
            result.1 = Some(newest.clone());
        }
    }

    tracing::trace!(
        "oldest version: {:?}, newest version: {:?}",
        result.0,
        result.1
    );

    result
}

pub(crate) async fn pop_bfs_level<T>(queue: &mut VecDeque<T>) -> Vec<T> {
    let current_level: Vec<_> = queue.drain(..).collect();
    tracing::info!("BFS pop a level, {} nodes", current_level.len());
    current_level
}

pub(crate) async fn push_next_level<T>(queue: &mut VecDeque<T>, next_nodes: Vec<T>) {
    let count = next_nodes.len();
    queue.extend(next_nodes);
    tracing::info!("BFS push next level, {} nodes", count);
}

// /// patch the target crate's Cargo.toml, lock the parent dependency to the specified version
// pub async fn patch_dep(
//     crate_dir: &Path,
//     dep_name: &str,
//     dep_version: &str,
// ) -> anyhow::Result<String> {
//     tracing::debug!("Patch the dependency: {} to {}", dep_name, dep_version);
//     let cargo_toml_path = crate_dir.join("Cargo.toml");
//     let original_content = tokio_fs::read_to_string(&cargo_toml_path)
//         .await
//         .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", cargo_toml_path, e))?;

//     let mut doc = original_content
//         .parse::<DocumentMut>()
//         .context("Failed to parse Cargo.toml")?;

//     let version_str = format!("={}", dep_version);

//     // set the dependency with comment
//     let set_dep_with_comment = |table: &mut toml_edit::Table, key: &str, new_version: &str| {
//         let item = table.get_mut(key);
//         if let Some(item) = item {
//             if let Some(inline_table) = item.as_table_mut() {
//                 // 形如 foo = { version = "...", ... }
//                 let old_version = inline_table
//                     .get("version")
//                     .and_then(|v| v.as_str())
//                     .unwrap_or("")
//                     .to_owned();
//                 inline_table["version"] = value(new_version);
//                 let comment = if old_version.is_empty() {
//                     format!(
//                         " auto lock the dependency version, from <none> to {}",
//                         new_version
//                     )
//                 } else {
//                     format!(
//                         " auto lock the dependency version, from {} to {}",
//                         old_version, new_version
//                     )
//                 };
//                 inline_table
//                     .decor_mut()
//                     .set_suffix(format!(" #{}", comment));
//             } else if let Some(val) = item.as_value_mut() {
//                 // 形如 foo = "1.2.3"
//                 let old_version = val.as_str().unwrap_or("").to_owned();
//                 *val = toml_edit::Value::from(new_version);
//                 let comment = if old_version.is_empty() {
//                     format!(
//                         " auto lock the dependency version, from <none> to {}",
//                         new_version
//                     )
//                 } else {
//                     format!(
//                         " auto lock the dependency version, from {} to {}",
//                         old_version, new_version
//                     )
//                 };
//                 val.decor_mut().set_suffix(format!(" #{}", comment));
//             }
//         }
//     };

//     // modify [dependencies]
//     if let Some(table) = doc["dependencies"].as_table_mut() {
//         set_dep_with_comment(table, dep_name, &version_str);
//     }
//     // modify [dev-dependencies]
//     if let Some(table) = doc["dev-dependencies"].as_table_mut() {
//         if table.contains_key(dep_name) {
//             set_dep_with_comment(table, dep_name, &version_str);
//         }
//     }
//     // modify [build-dependencies]
//     if let Some(table) = doc["build-dependencies"].as_table_mut() {
//         if table.contains_key(dep_name) {
//             set_dep_with_comment(table, dep_name, &version_str);
//         }
//     }

//     tokio_fs::write(&cargo_toml_path, doc.to_string())
//         .await
//         .context("Failed to write back Cargo.toml")?;

//     Ok(original_content)
// }

/// Ensure a vendored copy of the specified dependency exists under
/// `<crate_dir>/vendor/<dep_name>-<dep_version>` and add a [patch.crates-io]
/// entry in Cargo.toml to use the local path. This avoids resolver issues
/// with yanked versions while keeping builds offline-capable.
pub async fn vendor_and_patch_dep(
    crate_dir: &Path,
    dep_name: &str,
    dep_version: &str,
) -> anyhow::Result<String> {
    let vendor_root = crate_dir.join("vendor");
    let vendor_dir = vendor_root.join(format!("{}-{}", dep_name, dep_version));
    let vendor_cargo = vendor_dir.join("Cargo.toml");

    // Prepare vendor directory by downloading and extracting the crate
    if !vendor_cargo.exists() {
        tokio_fs::create_dir_all(&vendor_root)
            .await
            .context("Failed to create vendor directory")?;

        // Download to a local archive inside vendor_root
        let archive_path = vendor_root.join(format!("{}-{}.crate", dep_name, dep_version));
        let download_url = format!(
            "https://crates.io/api/v1/crates/{}/{}/download",
            dep_name, dep_version
        );

        tracing::info!(
            "Vendoring {}:{} -> {}",
            dep_name,
            dep_version,
            vendor_dir.display()
        );

        // If archive missing, fetch it
        if !archive_path.exists() {
            let output = Command::new("curl")
                .args(["-fL", &download_url, "-o", &archive_path.to_string_lossy()])
                .output()
                .await
                .context("Failed to execute curl for vendoring")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!(
                    "curl failed downloading {}:{}: {}",
                    dep_name,
                    dep_version,
                    stderr
                ));
            }
        }

        // Extract into vendor_root (archive contains <name>-<version>/)
        let output = Command::new("tar")
            .args([
                "-xzf",
                &archive_path.to_string_lossy(),
                "-C",
                &vendor_root.to_string_lossy(),
            ])
            .output()
            .await
            .context("Failed to execute tar for vendoring")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "tar failed extracting {}: {}",
                archive_path.display(),
                stderr
            ));
        }

        // Basic validation
        if !vendor_cargo.exists() {
            return Err(anyhow::anyhow!(
                "Vendored crate missing Cargo.toml: {}",
                vendor_dir.display()
            ));
        }
    }

    // Patch Cargo.toml to add [patch.crates-io] entry pointing to vendor path
    let cargo_toml_path = crate_dir.join("Cargo.toml");
    let original_content = tokio_fs::read_to_string(&cargo_toml_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", cargo_toml_path, e))?;

    let mut doc = original_content
        .parse::<DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    // Ensure [patch.crates-io]
    let patch_table = doc
        .entry("patch")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .unwrap()
        .entry("crates-io")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .unwrap();

    // Set dep_name = { path = "vendor/<name>-<version>" }
    let mut inline = toml_edit::InlineTable::new();
    inline.insert(
        "path",
        toml_edit::value(format!("vendor/{}-{}", dep_name, dep_version))
            .into_value()
            .unwrap(),
    );
    let mut item = toml_edit::Item::Value(toml_edit::Value::InlineTable(inline));
    // Add a helpful comment
    if let Some(val) = item.as_value_mut() {
        val.decor_mut().set_suffix(format!(
            " # auto use vendored {}:{} to avoid yanked resolution",
            dep_name, dep_version
        ));
    }
    patch_table.insert(dep_name, item);

    tokio_fs::write(&cargo_toml_path, doc.to_string())
        .await
        .context("Failed to write back Cargo.toml with [patch.crates-io]")?;

    // // Finally, keep version pinned in [dependencies] as well (optional)
    // let _ = patch_dep(crate_dir, dep_name, dep_version).await?;

    Ok(original_content)
}

pub async fn copy_dir(from: &Path, to: &Path, overwrite: bool) -> anyhow::Result<()> {
    let from_path = from.to_path_buf();
    let to_path = to.to_path_buf();

    // 确保源目录存在
    if !from_path.exists() {
        return Err(anyhow::anyhow!(
            "Source directory does not exist: {}",
            from_path.display()
        ));
    }

    // 确保目标目录存在
    if !to_path.exists() {
        tokio_fs::create_dir_all(&to_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to create target directory {}: {}",
                to_path.display(),
                e
            )
        })?;
    }

    // 添加重试机制来处理文件消失的问题
    let max_retries = 3;
    let mut last_error = None;

    for attempt in 0..max_retries {
        tracing::debug!(
            "Copying directory from {} to {} (attempt {}/{})",
            from_path.display(),
            to_path.display(),
            attempt + 1,
            max_retries
        );

        // 使用 rsync 进行复制，更可靠且支持增量复制
        let mut cmd = tokio::process::Command::new("rsync");
        cmd.args(["-a", "--delete", "--partial", "--inplace"]);

        if !overwrite {
            cmd.arg("--ignore-existing");
        }

        // 添加更多选项来处理文件消失问题
        cmd.args(["--no-whole-file", "--checksum"]);

        cmd.args([
            &format!("{}/", from_path.to_string_lossy()), // 源目录加斜杠表示复制内容
            &to_path.to_string_lossy().into_owned(),
        ]);

        let output = cmd
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to execute rsync command: {}", e))?;

        // 检查退出状态
        let exit_code = output.status.code().unwrap_or(-1);

        // rsync退出码24表示部分文件传输失败（文件消失等），但其他文件可能成功
        if exit_code == 24 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "rsync completed with warnings (exit code 24): {}. Attempt {}/{}",
                stderr,
                attempt + 1,
                max_retries
            );

            // 验证关键文件是否存在
            if validate_copied_files(&from_path, &to_path).await {
                tracing::info!("Copy completed successfully despite warnings");
                return Ok(());
            } else {
                last_error = Some(anyhow::anyhow!(
                    "Copy validation failed after rsync warnings: {}",
                    stderr
                ));
                continue;
            }
        } else if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            last_error = Some(anyhow::anyhow!(
                "rsync failed with exit code {}: {}",
                exit_code,
                stderr
            ));

            if attempt < max_retries - 1 {
                tracing::warn!(
                    "rsync failed, retrying in 1 second... (attempt {}/{})",
                    attempt + 1,
                    max_retries
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        } else {
            // 成功完成
            tracing::debug!("Copy completed successfully");
            return Ok(());
        }
    }

    // 所有重试都失败了
    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Failed to copy directory from {} to {} after {} attempts",
            from.to_string_lossy(),
            to.to_string_lossy(),
            max_retries
        )
    }))
}

/// 验证复制的文件是否完整
async fn validate_copied_files(from: &Path, to: &Path) -> bool {
    // 检查关键文件是否存在
    let critical_files = ["Cargo.toml", "src/lib.rs", "src/main.rs"];

    for file in &critical_files {
        let from_file = from.join(file);
        let to_file = to.join(file);

        // 如果源文件存在，目标文件也应该存在
        if from_file.exists() && !to_file.exists() {
            tracing::warn!("Critical file missing after copy: {}", to_file.display());
            return false;
        }
    }

    // 检查目录结构
    if let Ok(mut entries) = tokio_fs::read_dir(from).await {
        let mut from_count = 0;
        let mut to_count = 0;

        while let Ok(Some(_)) = entries.next_entry().await {
            from_count += 1;
        }

        if let Ok(mut entries) = tokio_fs::read_dir(to).await {
            while let Ok(Some(_)) = entries.next_entry().await {
                to_count += 1;
            }
        }

        // 如果目标目录文件数量明显少于源目录，可能复制不完整
        if to_count < from_count / 2 {
            tracing::warn!(
                "Target directory has significantly fewer files ({} vs {})",
                to_count,
                from_count
            );
            return false;
        }
    }

    true
}
