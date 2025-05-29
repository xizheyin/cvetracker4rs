use std::collections::VecDeque;

use semver::{Version, VersionReq};

use crate::model::ReverseDependency;

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
