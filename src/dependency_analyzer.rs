use anyhow::Result;
use futures::stream::{self as futures_stream, StreamExt};
use semver::Version;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::database::Database;
use crate::dir::CrateWorkspaceFileSystemManager;
use crate::model::Krate;
use crate::{callgraph, utils};

const MAX_CONCURRENT_TASKS: usize = 8;

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
    pub async fn new() -> Result<Self> {
        let database = Database::new().await?;
        Ok(Self {
            database: Arc::new(database),
            fs_manager: Arc::new(Mutex::new(CrateWorkspaceFileSystemManager::new())),
        })
    }

    pub async fn analyze(
        &self,
        cve_id: &str,
        crate_name: &str,
        version_range: &str,
        function_path: &str,
    ) -> Result<()> {
        let root_idx = self
            .fs_manager
            .lock()
            .await
            .create_root(cve_id, crate_name)
            .await?;
        let versions = self.database.query_crate_versions(crate_name).await?;
        // select oldest and newest versions that match the version range
        let two_end_versions: Vec<(usize, Version)> =
            crate::utils::select_two_end_vers(versions, version_range).await;

        let mut bfs_queue = VecDeque::new();

        // push CVE node to bfs_queue
        for (_, version) in two_end_versions {
            let ver_str = &version.to_string();
            let cve_krate =
                Krate::create(crate_name, ver_str, root_idx, self.fs_manager.clone()).await?;
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
                    .process_single_bfs_node(bfs_node, &target_function_path)
                    .await
            })
            .buffer_unordered(MAX_CONCURRENT_TASKS)
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
            .then(|reverse_dependency| {
                let rev_name = reverse_dependency.name.clone();
                let rev_ver = reverse_dependency.version.clone();
                let fs_manager = self.fs_manager.clone();
                let parent = bfs_node.clone();
                async move {
                    Krate::create(&rev_name, &rev_ver, parent.krate.ws_idx, fs_manager)
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
            .filter_map(|x| async { x }) // 直接过滤掉None
            .collect::<Vec<_>>()
            .await;

        Ok(dependent_krates)
    }

    async fn check_bfs_node_vulnerable(
        &self,
        bfs_node: Arc<BFSNode>,
        target_function_path: &str,
    ) -> Result<bool> {
        let working_dir = bfs_node
            .krate
            .get_working_dir(self.fs_manager.clone())
            .await;
        if let Some(parent) = &bfs_node.parent {
            utils::patch_dep(&working_dir, &parent.krate.name, &parent.krate.version).await?;

            let result = self
                .analyze_function_calls(&bfs_node.krate, target_function_path)
                .await;

            return Ok(result?.is_some());
        }
        Ok(true)
    }

    async fn analyze_function_calls(
        &self,
        krate: &Krate,
        function_path: &str,
    ) -> Result<Option<String>> {
        let original_dir = utils::get_current_dir();
        let crate_dir = krate.get_working_dir(self.fs_manager.clone()).await;

        let analysis_result = callgraph::run_function_analysis(&crate_dir, function_path).await?;

        utils::set_current_dir(&original_dir).await?;
        krate.cargo_clean(self.fs_manager.clone()).await?;

        Ok(analysis_result)
    }
}
