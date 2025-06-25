use crate::database::Database;
use crate::dir::CrateWorkspaceFileSystemManager;
use crate::model::Krate;
use crate::{callgraph, utils};
use anyhow::Result;
use futures::stream::{self as futures_stream, StreamExt};
use semver::Version;
use std::collections::VecDeque;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct BFSNode {
    pub krate: Krate,
    pub parent: Option<Arc<BFSNode>>,
}

#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {
    database: Arc<Database>,
    fs_manager: Arc<Mutex<CrateWorkspaceFileSystemManager>>,
}

impl DependencyAnalyzer {
    pub async fn new(cve_id: &str) -> Result<Self> {
        let database = Database::new().await?;
        Ok(Self {
            database: Arc::new(database),
            fs_manager: Arc::new(Mutex::new(
                CrateWorkspaceFileSystemManager::new(cve_id).await?,
            )),
        })
    }

    pub async fn analyze(
        &self,
        crate_name: &str,
        version_range: &str,
        function_path: &str,
    ) -> Result<()> {
        let versions = self.database.query_crate_versions(crate_name).await?;
        // select oldest and newest versions that match the version range
        let two_end_versions: Vec<(usize, Version)> =
            crate::utils::select_two_end_vers(versions, version_range).await;

        let mut bfs_queue = VecDeque::new();

        // push CVE node to bfs_queue
        for (_, version) in two_end_versions {
            let ver_str = &version.to_string();
            let cve_krate = Krate::create(crate_name, ver_str, 0, self.fs_manager.clone()).await?;
            let bfs_node = Arc::new(BFSNode {
                krate: cve_krate,
                parent: None,
            });
            bfs_queue.push_back(bfs_node);
        }

        self.bfs(bfs_queue, function_path).await?;

        Ok(())
    }

    async fn bfs(
        &self,
        mut queue: VecDeque<Arc<BFSNode>>,
        target_function_path: &str,
    ) -> Result<()> {
        while !queue.is_empty() {
            let current_level = utils::pop_bfs_level(&mut queue).await;
            let results = self
                .process_bfs_level(current_level, target_function_path)
                .await?;
            utils::push_next_level(&mut queue, results).await;
        }
        Ok(())
    }

    /// process a level of BFS
    async fn process_bfs_level(
        &self,
        current_level: Vec<Arc<BFSNode>>,
        target_function_path: &str,
    ) -> Result<Vec<Arc<BFSNode>>> {
        let analyzer = Arc::new(self.clone());
        Ok(futures_stream::iter(current_level)
            .map(async |bfs_node| {
                analyzer
                    .process_single_bfs_node(bfs_node, target_function_path)
                    .await
            })
            .buffer_unordered(
                env::var("MAX_CONCURRENT_BFS_NODES")
                    .unwrap_or("32".to_string())
                    .parse::<usize>()
                    .unwrap(),
            )
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>())
    }

    async fn process_single_bfs_node(
        &self,
        bfs_node: Arc<BFSNode>,
        target_function_path: &str,
    ) -> Result<Vec<Arc<BFSNode>>> {
        // check if the node is vulnerable
        if !self
            .check_bfs_node_vulnerable(bfs_node.clone(), target_function_path)
            .await?
        {
            return Ok(vec![]);
        }

        // get reverse dependencies in range of vulnerable version
        let selected_dependents =
            utils::get_reverse_deps_for_krate(&self.database, &bfs_node.krate).await?;

        // create new BFS nodes for reverse dependencies
        let dependent_krates = futures_stream::iter(selected_dependents)
            .map(|reverse_dependency| {
                let rev_name = reverse_dependency.name.clone();
                let rev_ver = reverse_dependency.version.clone();
                let fs_manager = self.fs_manager.clone();
                let parent = bfs_node.clone();
                async move {
                    Krate::create(&rev_name, &rev_ver, parent.krate.dir_idx, fs_manager)
                        .await
                        .ok()
                        .map(|dep_krate| {
                            Arc::new(BFSNode {
                                krate: dep_krate,
                                parent: Some(parent),
                            })
                        })
                }
            })
            .buffer_unordered(
                env::var("MAX_CONCURRENT_TASKS")
                    .unwrap_or("32".to_string())
                    .parse::<usize>()
                    .unwrap(),
            )
            .filter_map(|x| async { x })
            .collect::<Vec<_>>()
            .await;

        Ok(dependent_krates)
    }

    async fn check_bfs_node_vulnerable(
        &self,
        bfs_node: Arc<BFSNode>,
        target_function_path: &str,
    ) -> Result<bool> {
        tracing::info!("Check if the node is vulnerable: {}", bfs_node.krate.name);
        let working_dir = bfs_node.krate.get_working_dir().await;
        if let Some(parent) = &bfs_node.parent {
            utils::patch_dep(&working_dir, &parent.krate.name, &parent.krate.version)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to patch dependency in {}: {}",
                        working_dir.display(),
                        e
                    )
                })?;

            tracing::debug!("Analyze function calls for {}", bfs_node.krate.name);
            let analysis_result =
                callgraph::run_function_analysis(&bfs_node.krate, target_function_path).await;
            bfs_node.krate.cargo_clean().await?;

            match analysis_result {
                Ok(Some(analysis_result)) => {
                    tracing::info!(
                        "!!!!!!!!!!!!!!!!!!!!!!!!!!!Function analysis result: {}",
                        analysis_result
                    );
                    return Ok(true);
                }
                Ok(None) => {
                    tracing::info!("No function analysis result, skip the crate");
                    return Ok(false);
                }
                Err(e) => {
                    tracing::error!("Function analysis failed: {}", e);
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
