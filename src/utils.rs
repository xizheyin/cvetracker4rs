use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

use anyhow::Context;
use futures::stream::{self as futures_stream, StreamExt};
use semver::{Version, VersionReq};
use tokio::fs as tokio_fs;
use toml_edit::{value, DocumentMut};

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
            .or_insert_with(Vec::new)
            .push(revdep.clone());
    }

    let selected_dependents = futures_stream::iter(dependents_map.iter_mut())
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

    tracing::info!(
        "oldest version: {:?}, newest version: {:?}",
        result.0,
        result.1
    );

    result
}

pub(crate) async fn pop_bfs_level<T>(queue: &mut VecDeque<T>) -> Vec<T> {
    let current_level: Vec<_> = queue.drain(..).collect();
    tracing::info!("BFS弹出一层，共 {} 个节点", current_level.len());
    current_level
}

pub(crate) async fn push_next_level<T>(queue: &mut VecDeque<T>, next_nodes: Vec<T>) {
    let count = next_nodes.len();
    queue.extend(next_nodes);
    tracing::info!("BFS推入下一层，共 {} 个节点", count);
}

/// patch the target crate's Cargo.toml, lock the parent dependency to the specified version
pub async fn patch_dep(
    crate_dir: &Path,
    dep_name: &str,
    dep_version: &str,
) -> anyhow::Result<String> {
    let cargo_toml_path = crate_dir.join("Cargo.toml");
    let original_content = tokio_fs::read_to_string(&cargo_toml_path).await?;

    let mut doc = original_content
        .parse::<DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    let version_str = format!("={}", dep_version);

    // set the dependency with comment
    let set_dep_with_comment = |table: &mut toml_edit::Table, key: &str, new_version: &str| {
        let old_version = table
            .get(key)
            .and_then(|item| item.as_value())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        table[key] = value(new_version);
        if let Some(val) = table[key].as_value_mut() {
            let comment = if old_version.is_empty() {
                format!(
                    " # auto lock the dependency version, from <none> to {}",
                    new_version
                )
            } else {
                format!(
                    " # auto lock the dependency version, from {} to {}",
                    old_version, new_version
                )
            };
            val.decor_mut().set_suffix(&comment);
        }
    };

    // modify [dependencies]
    if let Some(table) = doc["dependencies"].as_table_mut() {
        set_dep_with_comment(table, dep_name, &version_str);
    }
    // modify [dev-dependencies]
    if let Some(table) = doc["dev-dependencies"].as_table_mut() {
        if table.contains_key(dep_name) {
            set_dep_with_comment(table, dep_name, &version_str);
        }
    }
    // modify [build-dependencies]
    if let Some(table) = doc["build-dependencies"].as_table_mut() {
        if table.contains_key(dep_name) {
            set_dep_with_comment(table, dep_name, &version_str);
        }
    }

    tokio_fs::write(&cargo_toml_path, doc.to_string())
        .await
        .context("Failed to write back Cargo.toml")?;

    Ok(original_content)
}

pub(crate) fn get_current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) async fn set_current_dir(dir: &PathBuf) -> anyhow::Result<()> {
    std::env::set_current_dir(dir).context("Failed to change directory")
}
