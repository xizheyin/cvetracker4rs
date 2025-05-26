use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use semver::{Version, VersionReq};
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::database::Database;
use crate::dir::CrateWorkspaceManager;
use crate::model::{Krate, ReverseDependency};

const MAX_CONCURRENT_TASKS: usize = 6;
const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct VisitedCrateVersion {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {
    database: Arc<Database>,
    crate_workspace_manager: Arc<CrateWorkspaceManager>,
    semaphore: Arc<Semaphore>,
}

impl DependencyAnalyzer {
    pub async fn new() -> Result<Self> {
        let database = Database::new().await?;
        Ok(Self {
            database: Arc::new(database),
            crate_workspace_manager: Arc::new(CrateWorkspaceManager::new()),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS)),
        })
    }

    /// 从给定的版本列表中选择最老和最新的版本
    fn select_oldest_and_newest_versions(
        &self,
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

    pub async fn analyze(
        &self,
        crate_name: &str,
        version_range: &str,
        function_path: &str,
    ) -> Result<()> {
        let version_req = self.parse_version_requirement(version_range).unwrap();
        let versions = self.database.query_crate_versions(crate_name).await?;

        tracing::info!(
            "Start analyzing crate: {}, version range: {}, {} versions",
            crate_name,
            version_req,
            versions.len()
        );

        // 筛选符合版本要求的版本
        let matched_versions = versions
            .into_iter()
            .filter_map(|version| {
                let parsed_version = Version::parse(&version).ok()?;
                version_req
                    .matches(&parsed_version)
                    .then_some(parsed_version)
            })
            .collect::<Vec<_>>();

        tracing::info!("找到符合版本要求的版本数: {}", matched_versions.len());

        // 只取最老和最新的版本（排序已在方法内部完成）
        let (oldest_version, newest_version) =
            self.select_oldest_and_newest_versions(matched_versions);

        if oldest_version.is_none() && newest_version.is_none() {
            tracing::info!("没有找到符合版本要求的版本");
            return Ok(());
        }

        let bfs_queue = vec![oldest_version, newest_version]
            .into_iter()
            .filter_map(|version| Some(Krate::new(crate_name, &version?.1.to_string())))
            .collect::<VecDeque<_>>();

        self.bfs_from_queue(bfs_queue, function_path).await?;

        Ok(())
    }

    async fn bfs_from_queue(
        &self,
        mut queue: VecDeque<Krate>,
        target_function_path: &str,
    ) -> Result<()> {
        tracing::info!("bfs queue size: {}", queue.len());

        let mut visited = HashSet::new();
        let mut level = 0;

        // pop current level
        let pop_bfs_level = |queue: &mut VecDeque<Krate>| -> Vec<Krate> {
            let mut current_level = Vec::new();
            while let Some(node) = queue.pop_front() {
                current_level.push(node);
            }
            tracing::info!("BFS弹出一层，共 {} 个节点", current_level.len());
            current_level
        };

        // push next level
        let push_next_level = |queue: &mut VecDeque<Krate>, next_nodes: Vec<Krate>| {
            let count = next_nodes.len();
            for node in next_nodes {
                queue.push_back(node);
            }
            tracing::info!("BFS推入下一层，共 {} 个节点", count);
        };

        // main loop of BFS Algorithm
        while !queue.is_empty() {
            level += 1;
            tracing::info!("BFS第{}层，队列长度:{}", level, queue.len());
            let current_level = pop_bfs_level(&mut queue);
            let results = self
                .process_bfs_level(current_level, target_function_path, &mut visited)
                .await?;
            push_next_level(&mut queue, results);
        }
        Ok(())
    }

    async fn process_bfs_level(
        &self,
        current_level: Vec<Krate>,
        target_function_path: &str,
        visited: &mut HashSet<VisitedCrateVersion>,
    ) -> Result<Vec<Krate>> {
        let analyzer = Arc::new(self.clone());
        let results = stream::iter(current_level)
            .map(|krate| {
                let analyzer = Arc::clone(&analyzer);
                let target_function_path = target_function_path.to_string();
                async move {
                    let _permit = analyzer.semaphore.acquire().await.unwrap();
                    analyzer
                        .process_single_bfs_node(krate, &target_function_path)
                        .await
                }
            })
            .buffer_unordered(MAX_CONCURRENT_TASKS) // 使用常量
            .collect::<Vec<_>>()
            .await;

        let mut next_nodes = Vec::new();
        let mut total_new = 0;
        for result in results {
            if let Ok(nodes) = result {
                total_new += nodes.len();
                for node in nodes {
                    let cv = VisitedCrateVersion {
                        name: node.name().to_string(),
                        version: node.version().to_string(),
                    };
                    if visited.insert(cv) {
                        next_nodes.push(node);
                    }
                }
            }
        }
        tracing::info!("process_bfs_level: 本层发现新节点:{}", total_new);
        Ok(next_nodes)
    }

    async fn process_single_bfs_node(
        &self,
        krate: Krate,
        target_function_path: &str,
    ) -> Result<Vec<Krate>> {
        let node_start_time = std::time::Instant::now();
        tracing::info!("准备查询依赖者: {} {}", krate.name(), krate.version());
        let precise_version = &krate.version();

        let reverse_dependencies = self.database.query_dependents(&krate.name()).await?;
        let reverse_dependencies_for_certain_version =
            Self::filter_dependents_by_version_req(reverse_dependencies, precise_version);

        let krate = Arc::new(krate); // 用 Arc 包裹
        tracing::info!(
            "query_dependents 返回 for {} {}",
            krate.name(),
            krate.version()
        );

        // 对每个crate名称的不同版本只选择最老和最新的
        let mut dependents_by_name: std::collections::HashMap<
            String,
            Vec<(Version, ReverseDependency)>,
        > = std::collections::HashMap::new();

        // 按crate名称分组并解析版本
        for dep in reverse_dependencies_for_certain_version {
            if let Ok(version) = Version::parse(&dep.version) {
                dependents_by_name
                    .entry(dep.name.clone())
                    .or_insert_with(Vec::new)
                    .push((version, dep));
            }
        }

        // 对每个crate名称，按版本排序并只选最老和最新版本
        let mut selected_dependents = Vec::new();
        let mut total_crates = 0;
        let mut total_versions = 0;

        for (name, versions) in dependents_by_name {
            total_crates += 1;
            let versions_count = versions.len();
            total_versions += versions_count;

            let selected = self.select_oldest_and_newest_versions(
                versions
                    .iter()
                    .map(|(version, _)| version.clone())
                    .collect(),
            );

            let selected_reverse_dependencies = vec![selected.0, selected.1]
                .into_iter()
                .filter_map(|x| {
                    if let Some((idx, _)) = x {
                        Some(versions[idx].1.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            selected_dependents.extend(selected_reverse_dependencies);
        }

        let selected_dependents_count = selected_dependents.len();
        tracing::info!(
            "共有{}个crate依赖，筛选后剩余{}个版本进行分析",
            total_crates,
            selected_dependents_count
        );

        let mut next_nodes = Vec::new();
        let mut total_progress_idx = 0;

        for (batch_idx, batch) in selected_dependents.chunks(BATCH_SIZE).enumerate() {
            tracing::info!("开始处理第{}批, 本批{}个依赖者", batch_idx + 1, batch.len());
            let batch_vec = batch.to_vec();
            let selected_dependents_len = selected_dependents.len();
            let batch_results = stream::iter(batch_vec.into_iter().enumerate())
                .map(|(idx, reverse_dependency)| {
                    let reverse_name = reverse_dependency.name.clone();
                    let reverse_version = reverse_dependency.version.clone();
                    let req_for_dep = reverse_dependency.req.clone();

                    let analyzer = self.clone();
                    let target_function_path = target_function_path.to_string();
                    let krate = Arc::clone(&krate);

                    total_progress_idx += 1;
                    tracing::info!(
                        "[依赖者进度 {}/{}] 正在分析依赖者: {} {}",
                        total_progress_idx,
                        selected_dependents_len,
                        reverse_name,
                        reverse_version
                    );
                    async move {
                        let _permit = analyzer.semaphore.acquire().await.unwrap();
                        let dep_krate = Krate::new(&reverse_name, &reverse_version);
                        let dep_dir = match dep_krate.get_crate_dir_path().await {
                            Ok(dir) => dir,
                            Err(e) => {
                                tracing::warn!(
                                    "[{}-{}] get_crate_dir_path失败: {}，跳过",
                                    reverse_name,
                                    reverse_version,
                                    e
                                );
                                return None;
                            }
                        };

                        tracing::info!(
                            "[{}-{}] 开始 patch_cargo_toml_with_parent",
                            reverse_name,
                            reverse_version
                        );

                        let patch_result = timeout(
                            Duration::from_secs(60),
                            Krate::patch_cargo_toml_with_parent(
                                &dep_dir,
                                &krate.name(),
                                &krate.version(),
                            ),
                        )
                        .await;

                        if let Ok(Ok(_)) = patch_result {
                            tracing::info!(
                                "[{}-{}] 完成 patch_cargo_toml_with_parent",
                                reverse_name,
                                reverse_version
                            );
                        } else {
                            tracing::warn!(
                                "[{}-{}] patch_cargo_toml_with_parent失败，跳过该crate后续分析",
                                reverse_name,
                                reverse_version
                            );
                            return None;
                        }

                        tracing::info!(
                            "[{}-{}] 开始 is_valid_dependent",
                            reverse_name,
                            reverse_version
                        );
                        let is_valid = analyzer
                            .is_valid_dependent(
                                &krate.version(),
                                &req_for_dep,
                                &reverse_name,
                                &reverse_version,
                                target_function_path.as_str(),
                            )
                            .await
                            .unwrap_or(false);
                        tracing::info!(
                            "[{}-{}] is_valid_dependent结果: {}",
                            reverse_name,
                            reverse_version,
                            is_valid
                        );

                        // 分析结束后删除 Cargo.lock
                        let cargo_lock_path = dep_dir.join("Cargo.lock");
                        let _ = tokio_fs::remove_file(&cargo_lock_path).await;

                        if is_valid {
                            tracing::info!(
                                "依赖者 {} {} 满足条件，加入下一层",
                                reverse_name,
                                reverse_version
                            );
                            Some(dep_krate)
                        } else {
                            tracing::info!(
                                "依赖者 {} {} 不满足条件，跳过",
                                reverse_name,
                                reverse_version
                            );
                            None
                        }
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_TASKS)
                .collect::<Vec<_>>()
                .await;

            tracing::info!(
                "第{}批处理完成，成功节点数: {}",
                batch_idx + 1,
                batch_results.iter().filter(|x| x.is_some()).count()
            );
            next_nodes.extend(batch_results.into_iter().filter_map(|x| x));
        }

        Ok(next_nodes)
    }

    /// filter reverse dependents by version requirement
    fn filter_dependents_by_version_req(
        dependents: Vec<ReverseDependency>,
        precise_version: &str,
    ) -> Vec<ReverseDependency> {
        let precise_version_parsed = semver::Version::parse(precise_version).ok();
        let filtered_dependents: Vec<ReverseDependency> = dependents
            .into_iter()
            .filter(|dep| {
                if let (Some(ver), Ok(dep_req)) = (
                    precise_version_parsed.as_ref(),
                    semver::VersionReq::parse(&dep.req),
                ) {
                    dep_req.matches(ver)
                } else {
                    false
                }
            })
            .collect();

        tracing::info!(
            "filter reverse dependents by version requirement, got {} dependents",
            filtered_dependents.len()
        );
        filtered_dependents
    }

    fn get_original_dir(&self) -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    // 主函数改名为更具体的名字
    async fn analyze_function_calls(
        &self,
        crate_name: &str,
        crate_version: &str,
        function_path: &str,
    ) -> Option<String> {
        // info!(
        //     "开始分析 crate {} {} 的函数调用: {}",
        //     crate_name, crate_version, function_path
        // );

        let krate = Krate::new(crate_name, crate_version);
        let original_dir = self.get_original_dir();

        // 准备分析环境
        let crate_dir = match self
            .prepare_analysis_environment(&krate, &original_dir)
            .await
        {
            Ok(dir) => dir,
            Err(e) => {
                // warn!("准备分析环境失败: {}", e);
                return None;
            }
        };

        // 运行函数调用分析工具
        let analysis_result = self.run_function_analysis(&crate_dir, function_path).await;

        // 清理环境并返回结果
        let result = self
            .cleanup_and_return_result(&krate, &crate_dir, &original_dir, analysis_result)
            .await;

        // 如果分析成功且有结果，保存到项目目录
        if let Some(_) = &result {
            if let Err(e) = self
                .save_analysis_result(crate_name, crate_version, &crate_dir)
                .await
            {
                warn!("保存分析结果失败: {}", e);
            }
        }

        result
    }

    // 准备分析环境
    async fn prepare_analysis_environment(
        &self,
        krate: &Krate,
        _original_dir: &PathBuf,
    ) -> Result<PathBuf> {
        // info!("准备分析环境: {} {}", krate.name(), krate.version());

        // 下载并解压crate（已自动判断是否已存在）
        let crate_dir = krate.get_crate_dir_path().await.context(format!(
            "无法下载或解压 crate: {} {}",
            krate.name(),
            krate.version()
        ))?;

        info!("crate目录已就绪: {}", crate_dir.display());
        Ok(crate_dir)
    }

    // 运行函数调用分析工具
    async fn run_function_analysis(
        &self,
        crate_dir: &PathBuf,
        function_path: &str,
    ) -> Result<Option<String>> {
        let src_dir = crate_dir.join("src");
        if !self
            .check_src_contain_target_function(&src_dir.to_string_lossy(), function_path)
            .await?
        {
            return Ok(None);
        }

        info!(
            "!!! 检查到目标函数{}，开始运行函数调用分析工具",
            function_path
        );

        let manifest_path = crate_dir.join("Cargo.toml");
        let output_dir = crate_dir.join("target"); // 工具生成在 crate 目录下

        let mut cmd = Command::new("call-cg4rs");
        cmd.args(&[
            "--find-callers",
            function_path,
            "--json-output",
            "--manifest-path",
            &manifest_path.to_string_lossy(),
            "--output-dir",
            &output_dir.to_string_lossy(),
        ]);

        // 设置超时时间为 4 分钟
        let call_cg_result = match timeout(Duration::from_secs(240), cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                warn!("call-cg4rs工具执行出错: {}，跳过该crate", e);
                return Ok(None);
            }
            Err(_) => {
                warn!("call-cg4rs工具分析超时(4分钟)，跳过该crate");
                return Ok(None);
            }
        };

        if !call_cg_result.status.success() {
            let stderr = String::from_utf8_lossy(&call_cg_result.stderr);
            warn!("call-cg4rs工具执行失败: {}", stderr);
            return Ok(None);
        }

        // 工具生成的 callers.json 路径
        let callers_json_path = output_dir.join("callers.json");
        if !callers_json_path.exists() {
            info!("未找到callers.json文件，说明没有函数调用");
            return Ok(None);
        }

        // 读取callers.json内容
        let callers_content =
            tokio_fs::read_to_string(&callers_json_path)
                .await
                .context(format!(
                    "读取callers.json文件失败: {}",
                    callers_json_path.display()
                ))?;

        Ok(Some(callers_content))
    }

    async fn check_src_contain_target_function(
        &self,
        src: &str,
        target_function_path: &str,
    ) -> Result<bool> {
        let function_name = target_function_path.split("::").last().unwrap();

        // 获取参数并添加到命令字符串
        let args: Vec<String> = vec![
            "-r".to_string(),
            "-n".to_string(),
            "--color=always".to_string(),
            function_name.to_string(),
            src.to_owned(),
        ];
        let mut grep_cmd = Command::new("grep");
        grep_cmd.args(args);
        tracing::info!("执行命令: {:?}", grep_cmd);
        // 调用grep命令执行
        let output = grep_cmd.output().await?;
        // 返回grep的退出状态码
        let status = output.status;
        if status.success() {
            return Ok(true);
        } else {
            // grep没有找到匹配内容时会返回非零状态码，这里特殊处理
            if output.stdout.is_empty() && status.code() == Some(1) {
                return Ok(false);
            } else {
                return Err(anyhow::anyhow!("搜索过程出错，退出码: {:?}", status.code()));
            }
        }
    }

    // 保存分析结果到项目目录
    async fn save_analysis_result(
        &self,
        crate_name: &str,
        crate_version: &str,
        crate_dir: &PathBuf,
    ) -> Result<()> {
        let src_path = crate_dir.join("target").join("callers.json");
        let result_filename = format!("{}-{}-callers.json", crate_name, crate_version);
        let dst_path = Path::new("target").join(&result_filename);

        // 确保 target 目录存在
        if let Some(parent) = dst_path.parent() {
            tokio_fs::create_dir_all(parent)
                .await
                .context("创建target目录失败")?;
        }

        // 复制文件
        tokio_fs::copy(&src_path, &dst_path).await.context(format!(
            "复制callers.json到目标目录失败: {} -> {}",
            src_path.display(),
            dst_path.display()
        ))?;

        info!("已保存结果到: {}", dst_path.display());
        Ok(())
    }

    // 清理环境并返回结果
    async fn cleanup_and_return_result(
        &self,
        krate: &Krate,
        _crate_dir: &PathBuf,
        _original_dir: &PathBuf,
        analysis_result: Result<Option<String>>,
    ) -> Option<String> {
        // 只清理下载的 .crate 压缩包，不删除解压后的项目文件夹
        let _ = krate.cleanup_crate_file().await;
        // 分析后自动 cargo clean，释放 target 空间
        let _ = krate.cargo_clean().await;

        match analysis_result {
            Ok(Some(result)) => {
                info!("crate {} {} 调用了目标函数", krate.name(), krate.version());
                Some(result)
            }
            Ok(None) => {
                info!(
                    "crate {} {} 没有调用目标函数",
                    krate.name(),
                    krate.version()
                );
                None
            }
            Err(e) => {
                warn!(
                    "分析 crate {} {} 时发生错误: {}",
                    krate.name(),
                    krate.version(),
                    e
                );
                None
            }
        }
    }

    // 解析版本要求
    pub fn parse_version_requirement(&self, version_range: &str) -> Result<VersionReq> {
        VersionReq::parse(version_range).map_err(|e| anyhow::anyhow!("解析版本范围失败: {}", e))
    }

    // 检查依赖者是否有效（版本匹配且调用了目标函数）
    async fn is_valid_dependent(
        &self,
        current_version: &str,
        req: &str,
        dep_name: &str,
        dep_version: &str,
        target_function_path: &str,
    ) -> Result<bool> {
        if let (Ok(ver), Ok(dep_req)) = (Version::parse(current_version), VersionReq::parse(req)) {
            if dep_req.matches(&ver) {
                let has_function_call = self
                    .analyze_function_calls(dep_name, dep_version, target_function_path)
                    .await
                    .is_some();
                if has_function_call {
                    info!(
                        "依赖者 {} {} 版本匹配且调用了目标函数",
                        dep_name, dep_version
                    );
                } else {
                    info!(
                        "依赖者 {} {} 版本匹配但未调用目标函数",
                        dep_name, dep_version
                    );
                }
                return Ok(has_function_call);
            }
        }
        Ok(false)
    }
}
