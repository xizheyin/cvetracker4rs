use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use tokio::fs as tokio_fs;
use tokio::process::Command;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct PackageId {
    pub name: String,
    pub version: String,
}

impl PackageId {
    pub fn key(&self) -> String {
        format!("{}:{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: PackageId,
    pub to: PackageId,
    pub dependency_type: DependencyType,
    pub version_requirement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyType {
    Normal,
    Dev,
    Build,
    Optional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub id: PackageId,
    pub categories: Vec<String>,
    pub downloads: Option<u64>,
    pub is_vulnerability_source: bool,
    pub vulnerability_functions: Vec<String>,
    pub ecosystem_domain: String, // web, cli, crypto, system, etc.
}

/// 依赖图构建器，专门用于分析Rust生态系统
pub struct DependencyGraph {
    pub packages: HashMap<String, PackageMetadata>,
    pub dependencies: Vec<DependencyEdge>,
    pub reverse_dependencies: HashMap<String, Vec<String>>, // 反向依赖索引
    pub vulnerability_sources: HashSet<String>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            packages: HashMap::new(),
            dependencies: Vec::new(),
            reverse_dependencies: HashMap::new(),
            vulnerability_sources: HashSet::new(),
        }
    }

    /// 从Cargo.toml和分析结果构建依赖图
    pub async fn build_from_analysis_results(&mut self, cve_id: &str) -> Result<()> {
        let analysis_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analysis_results");
        if !analysis_dir.exists() {
            return Ok(());
        }

        let mut dir_entries = tokio_fs::read_dir(&analysis_dir).await?;
        
        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let fname = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };

            let suffix = format!("-{}.txt", cve_id);
            if let Some(package_info) = fname.strip_suffix(&suffix) {
                if let Some((name, version)) = package_info.rsplit_once('-') {
                    let package_id = PackageId {
                        name: name.to_string(),
                        version: version.to_string(),
                    };

                    // 读取分析结果
                    let content = tokio_fs::read_to_string(&path).await?;
                    if let Ok(json) = serde_json::from_str::<Value>(&content) {
                        self.process_analysis_result(&package_id, &json).await?;
                    }
                }
            }
        }

        self.build_reverse_index();
        Ok(())
    }

    /// 处理单个包的分析结果
    async fn process_analysis_result(&mut self, package_id: &PackageId, analysis_data: &Value) -> Result<()> {
        let mut vulnerability_functions = Vec::new();
        let mut is_vulnerability_source = false;

        // 解析函数调用信息
        if let Some(array) = analysis_data.as_array() {
            for file_obj in array {
                if let Some(file_content) = file_obj.get("file-content") {
                    if let Some(callers) = file_content.get("callers").and_then(|v| v.as_array()) {
                        if !callers.is_empty() {
                            is_vulnerability_source = true;
                        }
                        
                        // 提取函数名
                        if let Some(file_name) = file_obj.get("file").and_then(|v| v.as_str()) {
                            if let Some(func_name) = self.extract_function_name(file_name) {
                                vulnerability_functions.push(func_name);
                            }
                        }
                    }
                }
            }
        }

        // 获取包的元数据
        let metadata = self.fetch_package_metadata(package_id).await?;
        let package_metadata = PackageMetadata {
            id: package_id.clone(),
            categories: metadata.categories.clone(),
            downloads: metadata.downloads,
            is_vulnerability_source,
            vulnerability_functions,
            ecosystem_domain: self.classify_ecosystem_domain(&metadata.categories),
        };

        let key = package_id.key();
        self.packages.insert(key.clone(), package_metadata);

        if is_vulnerability_source {
            self.vulnerability_sources.insert(key);
        }

        // 获取依赖关系
        self.fetch_dependencies(package_id).await?;

        Ok(())
    }

    /// 提取函数名从文件名
    fn extract_function_name(&self, file_name: &str) -> Option<String> {
        file_name
            .strip_prefix("callers-")
            .and_then(|s| s.strip_suffix(".json"))
            .map(|s| s.to_string())
    }

    /// 分类生态系统域
    fn classify_ecosystem_domain(&self, categories: &[String]) -> String {
        for category in categories {
            match category.as_str() {
                "web-programming" | "web" | "http" => return "web".to_string(),
                "command-line-utilities" | "cli" => return "cli".to_string(),
                "cryptography" | "crypto" => return "crypto".to_string(),
                "network-programming" | "network" => return "network".to_string(),
                "database" | "database-implementations" => return "database".to_string(),
                "game-development" | "games" => return "games".to_string(),
                "gui" | "graphics" => return "gui".to_string(),
                "science" | "mathematics" => return "science".to_string(),
                _ => continue,
            }
        }
        "other".to_string()
    }

    /// 获取包的元数据（从crates.io API）
    async fn fetch_package_metadata(&self, _package_id: &PackageId) -> Result<CrateMetadata> {
        // 这里可以调用crates.io API获取更详细的元数据
        // 为了简化，这里返回默认值
        Ok(CrateMetadata {
            categories: vec!["unknown".to_string()],
            downloads: None,
        })
    }

    /// 获取包的依赖关系
    async fn fetch_dependencies(&mut self, package_id: &PackageId) -> Result<()> {
        // 使用cargo metadata命令获取依赖信息
        // 这里需要在包的工作目录中执行
        let working_dir = self.get_package_working_dir(package_id);
        
        if !working_dir.exists() {
            return Ok(());
        }

        let output = Command::new("cargo")
            .args(&["metadata", "--format-version", "1", "--no-deps"])
            .current_dir(&working_dir)
            .output()
            .await?;

        if output.status.success() {
            let metadata_str = String::from_utf8_lossy(&output.stdout);
            if let Ok(metadata) = serde_json::from_str::<Value>(&metadata_str) {
                self.parse_cargo_metadata(package_id, &metadata)?;
            }
        }

        Ok(())
    }

    /// 解析Cargo元数据
    fn parse_cargo_metadata(&mut self, package_id: &PackageId, metadata: &Value) -> Result<()> {
        if let Some(packages) = metadata.get("packages").and_then(|v| v.as_array()) {
            for package in packages {
                if let Some(dependencies) = package.get("dependencies").and_then(|v| v.as_array()) {
                    for dep in dependencies {
                        if let (Some(name), Some(req)) = (
                            dep.get("name").and_then(|v| v.as_str()),
                            dep.get("req").and_then(|v| v.as_str())
                        ) {
                            let dep_type = match dep.get("kind").and_then(|v| v.as_str()) {
                                Some("dev") => DependencyType::Dev,
                                Some("build") => DependencyType::Build,
                                _ => DependencyType::Normal,
                            };

                            // 简化版本：使用req作为版本
                            let dep_package = PackageId {
                                name: name.to_string(),
                                version: req.to_string(),
                            };

                            let edge = DependencyEdge {
                                from: package_id.clone(),
                                to: dep_package,
                                dependency_type: dep_type,
                                version_requirement: req.to_string(),
                            };

                            self.dependencies.push(edge);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 获取包的工作目录
    fn get_package_working_dir(&self, package_id: &PackageId) -> PathBuf {
        // 这里需要根据你的目录结构来实现
        // 假设工作目录在某个地方
        PathBuf::from("working_dir").join(&package_id.name).join(&package_id.version)
    }

    /// 构建反向依赖索引
    fn build_reverse_index(&mut self) {
        self.reverse_dependencies.clear();
        
        for edge in &self.dependencies {
            let to_key = edge.to.key();
            let from_key = edge.from.key();
            
            self.reverse_dependencies
                .entry(to_key)
                .or_insert_with(Vec::new)
                .push(from_key);
        }
    }

    /// 计算从漏洞源到目标包的传播路径
    pub fn find_propagation_paths(&self, target: &PackageId, max_depth: usize) -> Vec<PropagationPath> {
        let mut paths = Vec::new();
        
        for source_key in &self.vulnerability_sources {
            if let Some(source_package) = self.packages.get(source_key) {
                let source_paths = self.bfs_propagation(&source_package.id, target, max_depth);
                paths.extend(source_paths);
            }
        }
        
        paths
    }

    /// 使用BFS查找传播路径
    fn bfs_propagation(&self, source: &PackageId, target: &PackageId, max_depth: usize) -> Vec<PropagationPath> {
        let mut paths = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((source.clone(), vec![source.clone()], 0));
        visited.insert(source.key());

        while let Some((current, path, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            // 查找依赖当前包的所有包
            if let Some(dependents) = self.reverse_dependencies.get(&current.key()) {
                for dependent_key in dependents {
                    if !visited.contains(dependent_key) {
                        visited.insert(dependent_key.clone());
                        
                        if let Some(dependent_package) = self.packages.get(dependent_key) {
                            let mut new_path = path.clone();
                            new_path.push(dependent_package.id.clone());

                            // 如果到达目标，创建路径
                            if dependent_package.id == *target {
                                paths.push(PropagationPath {
                                    id: format!("{}->{}",
                                               source.key(), target.key()),
                                    source: source.clone(),
                                    target: target.clone(),
                                    path: new_path.clone(),
                                    total_depth: depth + 1,
                                    vulnerability_functions: self.get_vulnerability_functions(source),
                                });
                            }

                            queue.push_back((dependent_package.id.clone(), new_path, depth + 1));
                        }
                    }
                }
            }
        }

        paths
    }

    /// 获取包的漏洞函数列表
    fn get_vulnerability_functions(&self, package_id: &PackageId) -> Vec<String> {
        self.packages
            .get(&package_id.key())
            .map(|p| p.vulnerability_functions.clone())
            .unwrap_or_default()
    }

    /// 计算包的依赖深度
    pub fn calculate_dependency_depth(&self, package_id: &PackageId) -> usize {
        let mut max_depth = 0;
        
        for source_key in &self.vulnerability_sources {
            if let Some(source_package) = self.packages.get(source_key) {
                let depth = self.calculate_depth(&source_package.id, package_id);
                max_depth = max_depth.max(depth);
            }
        }
        
        max_depth
    }

    /// 计算两个包之间的距离
    fn calculate_depth(&self, from: &PackageId, to: &PackageId) -> usize {
        if from == to {
            return 0;
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((from.clone(), 0));
        visited.insert(from.key());

        while let Some((current, depth)) = queue.pop_front() {
            if let Some(dependents) = self.reverse_dependencies.get(&current.key()) {
                for dependent_key in dependents {
                    if !visited.contains(dependent_key) {
                        visited.insert(dependent_key.clone());
                        
                        if let Some(dependent_package) = self.packages.get(dependent_key) {
                            if dependent_package.id == *to {
                                return depth + 1;
                            }
                            queue.push_back((dependent_package.id.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        usize::MAX // 未找到路径
    }

    /// 计算包的中心性分数
    pub fn calculate_centrality_scores(&self) -> BTreeMap<String, f64> {
        let mut scores = BTreeMap::new();
        let total_packages = self.packages.len() as f64;

        for (package_key, _) in &self.packages {
            // 度中心性：连接数 / (总节点数 - 1)
            let mut degree = 0;
            
            // 出度：该包依赖的包数
            for edge in &self.dependencies {
                if edge.from.key() == *package_key {
                    degree += 1;
                }
            }
            
            // 入度：依赖该包的包数
            if let Some(dependents) = self.reverse_dependencies.get(package_key) {
                degree += dependents.len();
            }

            let centrality = if total_packages > 1.0 {
                degree as f64 / (total_packages - 1.0)
            } else {
                0.0
            };

            scores.insert(package_key.clone(), centrality);
        }

        scores
    }

    /// 识别关键传播节点
    pub fn identify_critical_nodes(&self) -> Vec<PackageId> {
        let centrality_scores = self.calculate_centrality_scores();
        let mut scored_packages: Vec<_> = centrality_scores
            .iter()
            .filter_map(|(key, score)| {
                self.packages.get(key).map(|p| (p.id.clone(), *score))
            })
            .collect();

        scored_packages.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored_packages.into_iter().take(10).map(|(id, _)| id).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationPath {
    pub id: String,
    pub source: PackageId,
    pub target: PackageId,
    pub path: Vec<PackageId>,
    pub total_depth: usize,
    pub vulnerability_functions: Vec<String>,
}

// 简化的包元数据结构
struct CrateMetadata {
    categories: Vec<String>,
    downloads: Option<u64>,
}
