use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use semver::{Version, VersionReq};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::database::Database;
use crate::dir::CrateWorkspaceFileSystemManager;
use crate::model::{Krate, ReverseDependency};
use crate::utils;

const MAX_CONCURRENT_TASKS: usize = 8;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct VisitedCrateVersion {
    pub name: String,
    pub version: String,
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
        for (_, version) in two_end_versions {
            let ver_str = &version.to_string();
            let krate =
                Krate::create(crate_name, ver_str, root_idx, self.fs_manager.clone()).await?;
            bfs_queue.push_back(krate);
        }
        self.bfs(bfs_queue, function_path).await?;

        Ok(())
    }

    async fn bfs(&self, mut queue: VecDeque<Krate>, target_function_path: &str) -> Result<()> {
        // main loop of BFS Algorithm
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
        current_level: Vec<Krate>,
        target_function_path: &str,
    ) -> Result<Vec<Krate>> {
        let analyzer = Arc::new(self.clone());
        Ok(stream::iter(current_level)
            .map(async |krate| {
                analyzer
                    .process_single_bfs_node(&krate, &target_function_path)
                    .await
            })
            .buffer_unordered(MAX_CONCURRENT_TASKS) // 使用常量
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>())
    }

    async fn process_single_bfs_node(
        &self,
        krate: &Krate,
        target_function_path: &str,
    ) -> Result<Vec<Krate>> {
        let selected_dependents = self.get_reverse_deps_for_krate(krate).await?;

        let batch_results = stream::iter(selected_dependents)
            .map(|reverse_dependency| {
                let rev_name = reverse_dependency.name.clone();
                let rev_ver = reverse_dependency.version.clone();
                let req = reverse_dependency.req.clone();

                let krate = Arc::new(krate.clone());

                async move {
                    let dep_krate =
                        Krate::create(&rev_name, &rev_ver, krate.ws_idx, self.fs_manager.clone())
                            .await
                            .ok()?;

                    let working_dir = dep_krate.get_working_dir(self.fs_manager.clone()).await;
                    utils::patch_dep(&working_dir, &krate.name, &krate.version)
                        .await
                        .expect(&format!(
                            "patch dep {} {} failed",
                            &krate.name, &krate.version
                        ));

                    match self
                        .is_valid_dependent(
                            &krate.version,
                            &req,
                            &rev_name,
                            &rev_ver,
                            target_function_path,
                        )
                        .await
                    {
                        Ok(_) => Some(dep_krate),
                        Err(e) => {
                            warn!(
                                "分析依赖者 {} {} 时发生错误: {}",
                                &krate.name, &krate.version, e
                            );
                            None
                        }
                    }
                }
            })
            .buffer_unordered(MAX_CONCURRENT_TASKS)
            .collect::<Vec<_>>()
            .await;

        Ok(batch_results.into_iter().flatten().collect::<Vec<_>>())
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
        let krate = Krate::create(crate_name, crate_version, todo!(), self.fs_manager.clone())
            .await
            .ok()?;
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
        let crate_dir = krate.fetch_and_unzip_crate().await.context(format!(
            "无法下载或解压 crate: {} {}",
            krate.name, krate.version
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

    // clean the environment and return the result
    async fn cleanup_and_return_result(
        &self,
        krate: &Krate,
        _crate_dir: &PathBuf,
        _original_dir: &PathBuf,
        analysis_result: Result<Option<String>>,
    ) -> Option<String> {
        // only clean the .crate file, keep the extracted directory
        let _ = krate.cleanup_crate_file().await;
        // clean the target directory after analysis
        let _ = krate.cargo_clean().await;

        match analysis_result {
            Ok(Some(result)) => {
                info!("crate {} {} 调用了目标函数", krate.name, krate.version);
                Some(result)
            }
            Ok(None) => {
                info!("crate {} {} 没有调用目标函数", krate.name, krate.version);
                None
            }
            Err(e) => {
                warn!(
                    "分析 crate {} {} 时发生错误: {}",
                    krate.name, krate.version, e
                );
                None
            }
        }
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

    async fn get_reverse_deps_for_krate(
        &self,
        krate: &Krate,
    ) -> anyhow::Result<Vec<ReverseDependency>> {
        let precise_version = &krate.version;

        let reverse_deps = self.database.query_dependents(&krate.name).await?;
        let reverse_deps_for_certain_version =
            utils::filter_dependents_by_version_req(reverse_deps, precise_version).await?;

        let mut dependents_map: std::collections::HashMap<String, Vec<ReverseDependency>> =
            std::collections::HashMap::new();

        for revdep in reverse_deps_for_certain_version {
            dependents_map
                .entry(revdep.name.clone())
                .or_insert_with(Vec::new)
                .push(revdep.clone());
        }

        let selected_dependents = stream::iter(dependents_map.iter_mut())
            .then(|(_, revdeps)| async move {
                utils::select_two_end_vers(
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
}
