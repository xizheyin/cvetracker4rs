use crate::database::Database;
use crate::dir::CrateWorkspaceFileSystemManager;
use crate::model::Krate;
use crate::{callgraph, utils};
use anyhow::Result;
use futures::stream::{self as futures_stream, StreamExt};
use semver::Version;
use std::collections::{HashSet, VecDeque};
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
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
    cve_id: String,
}

impl DependencyAnalyzer {
    pub async fn new(cve_id: &str) -> Result<Self> {
        let database = Database::new().await?;
        Ok(Self {
            database: Arc::new(database),
            fs_manager: Arc::new(Mutex::new(
                CrateWorkspaceFileSystemManager::new(cve_id).await?,
            )),
            cve_id: cve_id.to_string(),
        })
    }

    pub async fn analyze(
        &self,
        crate_name: &str,
        version_range: &str,
        function_paths: &str,
    ) -> Result<()> {
        // 为每个进程创建唯一的日志文件名
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let logs_dir = std::env::current_dir()
            .unwrap()
            .join(format!("logs_cg4rs/{}_{}", self.cve_id, timestamp));
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

        self.bfs(bfs_queue, function_paths, &logs_dir).await?;

        Ok(())
    }

    async fn bfs(
        &self,
        mut queue: VecDeque<Arc<BFSNode>>,
        target_function_paths: &str,
        logs_dir: &PathBuf,
    ) -> Result<()> {
        let mut visited = HashSet::new();
        while !queue.is_empty() {
            let current_level = utils::pop_bfs_level(&mut queue).await;
            let results = self
                .process_bfs_level(current_level, target_function_paths, &logs_dir)
                .await?;

            // filter out the nodes that have been visited
            let results_without_visited = results
                .into_iter()
                .filter(|node| {
                    let key = (node.krate.name.clone(), node.krate.version.clone());
                    if visited.contains(&key) {
                        false
                    } else {
                        visited.insert(key);
                        true
                    }
                })
                .collect::<Vec<_>>();

            utils::push_next_level(&mut queue, results_without_visited).await;
        }
        Ok(())
    }

    /// process a level of BFS
    async fn process_bfs_level(
        &self,
        current_level: Vec<Arc<BFSNode>>,
        target_function_paths: &str,
        logs_dir: &PathBuf,
    ) -> Result<Vec<Arc<BFSNode>>> {
        let analyzer = Arc::new(self.clone());
        Ok(futures_stream::iter(current_level)
            .map(async |bfs_node| {
                analyzer
                    .process_single_bfs_node(bfs_node, target_function_paths, &logs_dir)
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
        target_function_paths: &str,
        logs_dir: &PathBuf,
    ) -> Result<Vec<Arc<BFSNode>>> {
        // check if the node is vulnerable
        if !self
            .check_bfs_node_vulnerable(
                bfs_node.clone(),
                target_function_paths,
                &self.cve_id,
                &logs_dir,
            )
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
                env::var("MAX_CONCURRENT_DEP_DOWNLOAD")
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
        target_function_paths: &str,
        cveid: &str,
        logs_dir: &PathBuf,
    ) -> Result<bool> {
        let krate_name = &bfs_node.krate.name;
        let krate_version = &bfs_node.krate.version;

        tracing::info!(
            "[{}:{}] Starting vulnerability check",
            krate_name,
            krate_version
        );
        let working_src_code_dir = bfs_node.krate.get_working_src_code_dir().await;
        if let Some(parent) = &bfs_node.parent {
            tracing::debug!(
                "[{}:{}] Patching dependency {}:{}",
                krate_name,
                krate_version,
                parent.krate.name,
                parent.krate.version
            );

            utils::patch_dep(
                &working_src_code_dir,
                &parent.krate.name,
                &parent.krate.version,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to patch dependency in {}: {}",
                    working_src_code_dir.display(),
                    e
                )
            })
            .unwrap();

            tracing::info!("[{cveid}:{krate_name}:{krate_version}] Starting function analysis");
            let analysis_result =
                callgraph::run_function_analysis(&bfs_node.krate, target_function_paths, &logs_dir)
                    .await;

            tracing::debug!("[{cveid}:{krate_name}:{krate_version}] Cleaning cargo cache");
            bfs_node.krate.cargo_clean().await?;

            match analysis_result {
                Ok(Some(analysis_result)) => {
                    tracing::info!(
                        "[{cveid}:{krate_name}:{krate_version}] Function analysis completed successfully"
                    );
                    let result_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("analysis_results")
                        .join(cveid);
                    if !result_dir.exists() {
                        fs::create_dir_all(&result_dir)?;
                    }
                    let filename =
                        format!("{}-{}.txt", bfs_node.krate.name, bfs_node.krate.version);
                    let filepath = result_dir.join(filename);
                    tracing::info!(
                        "[{cveid}:{krate_name}:{krate_version}] Writing result to: {:?}",
                        filepath
                    );
                    fs::write(filepath, &analysis_result)?;
                    return Ok(true);
                }
                Ok(None) => {
                    tracing::info!("[{cveid}:{krate_name}:{krate_version}] No function analysis result, skipping crate");
                    return Ok(false);
                }
                Err(e) => {
                    tracing::error!(
                        "[{cveid}:{krate_name}:{krate_version}] Function analysis failed: {}",
                        e
                    );
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
