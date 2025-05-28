use semver::{Version, VersionReq};

pub(crate) async fn select_two_end_versions_by_version_range(
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
