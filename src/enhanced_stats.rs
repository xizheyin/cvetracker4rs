use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use tokio::fs as tokio_fs;

/// 表示一个包的版本信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageVersion {
    pub name: String,
    pub version: String,
}

/// 依赖关系信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub from: PackageVersion,
    pub to: PackageVersion,
    pub dependency_type: String, // "direct", "dev", "build"
}

/// 传播路径中的一个节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationNode {
    pub package: PackageVersion,
    pub function_calls: Vec<String>, // 在此包中调用的漏洞函数
    pub depth: usize,               // 从漏洞源的距离
    pub is_direct_dependency: bool, // 是否直接依赖漏洞包
}

/// 完整的传播路径
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationPath {
    pub id: String,                      // 路径唯一标识
    pub source: PackageVersion,          // 漏洞源包
    pub target: PackageVersion,          // 最终使用包
    pub path: Vec<PropagationNode>,      // 传播路径
    pub total_depth: usize,              // 路径总长度
    pub vulnerability_functions: Vec<String>, // 涉及的漏洞函数
}

/// 依赖层级统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DependencyLayerStats {
    pub layer: usize,                    // 层级（0=直接依赖，1=间接依赖等）
    pub package_count: usize,            // 该层级包数量
    pub function_call_count: usize,      // 该层级函数调用数量
    pub packages: Vec<PackageVersion>,   // 该层级的包列表
}

/// 影响范围统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ImpactScopeStats {
    pub direct_affected_packages: usize,    // 直接受影响包数
    pub indirect_affected_packages: usize,  // 间接受影响包数
    pub max_propagation_depth: usize,       // 最大传播深度
    pub avg_propagation_depth: f64,         // 平均传播深度
    pub propagation_width_by_depth: BTreeMap<usize, usize>, // 每个深度的包数量
    pub critical_propagation_nodes: Vec<PackageVersion>, // 关键传播节点（被多个路径经过）
}

/// 函数级传播统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FunctionPropagationStats {
    pub function_name: String,
    pub total_callers: usize,
    pub direct_callers: usize,              // 直接调用者
    pub indirect_callers: usize,            // 间接调用者
    pub max_call_depth: usize,              // 最大调用深度
    pub propagation_paths: Vec<PropagationPath>, // 传播路径
    pub affected_domains: Vec<String>,      // 受影响的应用域（如：web, cli, crypto等）
}

/// 时间维度统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TemporalStats {
    pub version_impact_timeline: BTreeMap<String, usize>, // 版本发布时间 -> 影响包数
    pub propagation_evolution: BTreeMap<String, ImpactScopeStats>, // 版本 -> 影响范围
}

/// 网络拓扑统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NetworkTopologyStats {
    pub total_nodes: usize,              // 总节点数
    pub total_edges: usize,              // 总边数
    pub clustering_coefficient: f64,     // 聚类系数
    pub average_path_length: f64,        // 平均路径长度
    pub centrality_scores: BTreeMap<String, f64>, // 包的中心性得分
    pub hub_packages: Vec<(PackageVersion, f64)>, // 关键枢纽包
}

/// 增强的全局统计信息
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EnhancedGlobalStats {
    pub cve_id: String,
    pub analysis_timestamp: String,
    
    // 基础统计
    pub total_packages: usize,
    pub total_versions: usize,
    pub total_function_calls: usize,
    
    // 依赖层级分析
    pub dependency_layers: Vec<DependencyLayerStats>,
    pub max_dependency_depth: usize,
    
    // 影响范围分析
    pub impact_scope: ImpactScopeStats,
    
    // 函数级统计
    pub function_stats: BTreeMap<String, FunctionPropagationStats>,
    
    // 传播路径分析
    pub all_propagation_paths: Vec<PropagationPath>,
    pub critical_paths: Vec<PropagationPath>, // 最重要的传播路径
    
    // 网络拓扑分析
    pub network_topology: NetworkTopologyStats,
    
    // 时间维度分析
    pub temporal_analysis: TemporalStats,
    
    // 包分类统计
    pub package_categories: BTreeMap<String, usize>, // 包类型 -> 数量
    pub ecosystem_distribution: BTreeMap<String, usize>, // 生态系统分布
    
    // 风险评估
    pub high_risk_packages: Vec<(PackageVersion, f64)>, // 高风险包及其风险得分
    pub vulnerability_hotspots: Vec<String>, // 漏洞热点函数
    
    // 修复建议
    pub recommended_fix_order: Vec<PackageVersion>, // 建议修复顺序
    pub fix_impact_estimation: BTreeMap<String, usize>, // 修复某包后减少的影响范围
}

impl EnhancedGlobalStats {
    pub fn new(cve_id: &str) -> Self {
        Self {
            cve_id: cve_id.to_string(),
            analysis_timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ..Default::default()
        }
    }
}

/// 依赖关系图构建器
pub struct DependencyGraphBuilder {
    pub nodes: HashMap<String, PackageVersion>,
    pub edges: Vec<DependencyInfo>,
    pub vulnerability_sources: HashSet<String>, // 漏洞源包
}

impl DependencyGraphBuilder {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            vulnerability_sources: HashSet::new(),
        }
    }
    
    pub fn add_package(&mut self, package: PackageVersion) {
        let key = format!("{}:{}", package.name, package.version);
        self.nodes.insert(key, package);
    }
    
    pub fn add_dependency(&mut self, from: PackageVersion, to: PackageVersion, dep_type: &str) {
        self.edges.push(DependencyInfo {
            from,
            to,
            dependency_type: dep_type.to_string(),
        });
    }
    
    pub fn mark_vulnerability_source(&mut self, package: &PackageVersion) {
        let key = format!("{}:{}", package.name, package.version);
        self.vulnerability_sources.insert(key);
    }
    
    /// 计算从漏洞源到所有包的传播路径
    pub fn compute_propagation_paths(&self) -> Vec<PropagationPath> {
        let mut paths = Vec::new();
        
        for source_key in &self.vulnerability_sources {
            if let Some(source_package) = self.nodes.get(source_key) {
                let source_paths = self.bfs_from_source(source_package);
                paths.extend(source_paths);
            }
        }
        
        paths
    }
    
    /// 从单个漏洞源使用BFS计算传播路径
    fn bfs_from_source(&self, source: &PackageVersion) -> Vec<PropagationPath> {
        let mut paths = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        
        let source_key = format!("{}:{}", source.name, source.version);
        queue.push_back((source.clone(), vec![PropagationNode {
            package: source.clone(),
            function_calls: vec![],
            depth: 0,
            is_direct_dependency: true,
        }], 0));
        visited.insert(source_key);
        
        while let Some((current_package, current_path, depth)) = queue.pop_front() {
            // 查找所有依赖当前包的包
            for edge in &self.edges {
                let to_key = format!("{}:{}", edge.to.name, edge.to.version);
                let from_key = format!("{}:{}", edge.from.name, edge.from.version);
                
                if to_key == format!("{}:{}", current_package.name, current_package.version) {
                    if !visited.contains(&from_key) {
                        visited.insert(from_key.clone());
                        
                        let mut new_path = current_path.clone();
                        new_path.push(PropagationNode {
                            package: edge.from.clone(),
                            function_calls: vec![], // 这里需要从分析结果中获取
                            depth: depth + 1,
                            is_direct_dependency: depth == 0,
                        });
                        
                        // 创建传播路径
                        paths.push(PropagationPath {
                            id: format!("{}->{}:{}", 
                                       format!("{}:{}", source.name, source.version),
                                       edge.from.name, edge.from.version),
                            source: source.clone(),
                            target: edge.from.clone(),
                            path: new_path.clone(),
                            total_depth: depth + 1,
                            vulnerability_functions: vec![], // 需要从分析结果中获取
                        });
                        
                        queue.push_back((edge.from.clone(), new_path, depth + 1));
                    }
                }
            }
        }
        
        paths
    }
    
    /// 计算网络拓扑统计
    pub fn compute_network_topology(&self) -> NetworkTopologyStats {
        let total_nodes = self.nodes.len();
        let total_edges = self.edges.len();
        
        // 计算聚类系数（简化版本）
        let clustering_coefficient = if total_nodes > 2 {
            let max_edges = total_nodes * (total_nodes - 1) / 2;
            total_edges as f64 / max_edges as f64
        } else {
            0.0
        };
        
        // 计算中心性得分（度中心性）
        let mut degree_count: HashMap<String, usize> = HashMap::new();
        for edge in &self.edges {
            let from_key = format!("{}:{}", edge.from.name, edge.from.version);
            let to_key = format!("{}:{}", edge.to.name, edge.to.version);
            *degree_count.entry(from_key).or_insert(0) += 1;
            *degree_count.entry(to_key).or_insert(0) += 1;
        }
        
        let mut centrality_scores = BTreeMap::new();
        let mut hub_packages = Vec::new();
        
        for (package_key, degree) in degree_count {
            let centrality = if total_nodes > 1 {
                degree as f64 / (total_nodes - 1) as f64
            } else {
                0.0
            };
            centrality_scores.insert(package_key.clone(), centrality);
            
            if let Some(package) = self.nodes.get(&package_key) {
                hub_packages.push((package.clone(), centrality));
            }
        }
        
        // 排序找出关键枢纽包
        hub_packages.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        hub_packages.truncate(10); // 只保留前10个
        
        NetworkTopologyStats {
            total_nodes,
            total_edges,
            clustering_coefficient,
            average_path_length: 1.0, // 简化值
            centrality_scores,
            hub_packages,
        }
    }
}

/// 统计分析器
pub struct EnhancedStatsAnalyzer {
    pub dependency_graph: DependencyGraphBuilder,
    pub function_call_data: HashMap<String, Value>, // package_name -> call_graph_data
}

impl EnhancedStatsAnalyzer {
    pub fn new() -> Self {
        Self {
            dependency_graph: DependencyGraphBuilder::new(),
            function_call_data: HashMap::new(),
        }
    }
    
    /// 从分析结果文件加载数据
    pub async fn load_analysis_results(&mut self, cve_id: &str) -> Result<()> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analysis_results");
        if !dir.exists() {
            return Ok(());
        }
        
        let mut dir_entries = tokio_fs::read_dir(&dir).await?;
        
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
                let content = tokio_fs::read_to_string(&path).await?;
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    self.function_call_data.insert(package_info.to_string(), json.clone());
                    
                    // 解析包名和版本
                    if let Some((name, version)) = package_info.rsplit_once('-') {
                        let package = PackageVersion {
                            name: name.to_string(),
                            version: version.to_string(),
                        };
                        self.dependency_graph.add_package(package.clone());
                        
                        // 检查是否包含漏洞函数调用
                        if self.contains_vulnerability_functions(&json) {
                            self.dependency_graph.mark_vulnerability_source(&package);
                            tracing::info!("Found vulnerability source: {}:{}", name, version);
                        }
                    }
                }
            }
        }
        
        tracing::info!("Loaded {} packages from analysis results", self.function_call_data.len());
        Ok(())
    }
    
    /// 检查包是否包含漏洞函数调用
    fn contains_vulnerability_functions(&self, analysis_data: &Value) -> bool {
        if let Some(array) = analysis_data.as_array() {
            for file_obj in array {
                if let Some(file_content) = file_obj.get("file-content") {
                    if let Some(callers) = file_content.get("callers").and_then(|v| v.as_array()) {
                        if !callers.is_empty() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    
    /// 分析依赖层级
    pub fn analyze_dependency_layers(&self) -> Vec<DependencyLayerStats> {
        let mut layers = Vec::new();
        
        // 简化实现：直接从加载的数据统计
        let mut depth_stats: BTreeMap<usize, DependencyLayerStats> = BTreeMap::new();
        
        // Layer 0: 所有包都作为直接依赖（因为我们没有真正的依赖关系数据）
        let mut total_function_calls = 0;
        let mut packages = Vec::new();
        
        for (package_name, analysis_data) in &self.function_call_data {
            if let Some((name, version)) = package_name.rsplit_once('-') {
                packages.push(PackageVersion {
                    name: name.to_string(),
                    version: version.to_string(),
                });
                
                // 统计函数调用数
                if let Some(array) = analysis_data.as_array() {
                    for file_obj in array {
                        if let Some(file_content) = file_obj.get("file-content") {
                            if let Some(callers) = file_content.get("callers").and_then(|v| v.as_array()) {
                                total_function_calls += callers.len();
                            }
                        }
                    }
                }
            }
        }
        
        if !packages.is_empty() {
            layers.push(DependencyLayerStats {
                layer: 0,
                package_count: packages.len(),
                function_call_count: total_function_calls,
                packages,
            });
        }
        
        layers
    }
    
    /// 分析影响范围
    pub fn analyze_impact_scope(&self) -> ImpactScopeStats {
        // 简化实现：基于实际加载的数据
        let total_packages = self.function_call_data.len();
        let vulnerability_sources = self.dependency_graph.vulnerability_sources.len();
        
        // 假设所有有数据的包都是直接受影响的
        let direct_affected = total_packages;
        let indirect_affected = 0; // 当前没有真正的传播路径数据
        
        let mut depth_distribution = BTreeMap::new();
        depth_distribution.insert(0, total_packages);
        
        ImpactScopeStats {
            direct_affected_packages: direct_affected,
            indirect_affected_packages: indirect_affected,
            max_propagation_depth: if total_packages > 0 { 1 } else { 0 },
            avg_propagation_depth: if total_packages > 0 { 1.0 } else { 0.0 },
            propagation_width_by_depth: depth_distribution,
            critical_propagation_nodes: Vec::new(),
        }
    }
    
    /// 生成完整的统计报告
    pub async fn generate_enhanced_stats(&self, cve_id: &str) -> Result<EnhancedGlobalStats> {
        let mut stats = EnhancedGlobalStats::new(cve_id);
        
        stats.total_packages = self.function_call_data.len();
        stats.dependency_layers = self.analyze_dependency_layers();
        stats.max_dependency_depth = stats.dependency_layers.iter()
            .map(|l| l.layer)
            .max()
            .unwrap_or(0);
        
        stats.impact_scope = self.analyze_impact_scope();
        stats.all_propagation_paths = self.dependency_graph.compute_propagation_paths();
        stats.network_topology = self.dependency_graph.compute_network_topology();
        
        // 计算函数级统计
        stats.function_stats = self.analyze_function_stats();
        
        // 计算总函数调用数
        stats.total_function_calls = stats.function_stats.values()
            .map(|f| f.total_callers)
            .sum();
        
        Ok(stats)
    }
    
    /// 分析函数级统计
    fn analyze_function_stats(&self) -> BTreeMap<String, FunctionPropagationStats> {
        let mut function_stats = BTreeMap::new();
        
        // 聚合所有函数的统计信息
        let mut function_totals: HashMap<String, usize> = HashMap::new();
        
        for (_package_name, analysis_data) in &self.function_call_data {
            if let Some(array) = analysis_data.as_array() {
                for file_obj in array {
                    if let Some(file_name) = file_obj.get("file").and_then(|v| v.as_str()) {
                        // 提取函数名
                        let func_name = file_name
                            .strip_prefix("callers-")
                            .and_then(|s| s.strip_suffix(".json"))
                            .unwrap_or(file_name)
                            .to_string();
                        
                        if let Some(file_content) = file_obj.get("file-content") {
                            if let Some(callers) = file_content.get("callers").and_then(|v| v.as_array()) {
                                *function_totals.entry(func_name.clone()).or_insert(0) += callers.len();
                            }
                        }
                    }
                }
            }
        }
        
        // 创建函数统计对象
        for (func_name, total_callers) in function_totals {
            function_stats.insert(func_name.clone(), FunctionPropagationStats {
                function_name: func_name,
                total_callers,
                direct_callers: total_callers, // 简化：假设都是直接调用
                indirect_callers: 0,
                max_call_depth: 1,
                propagation_paths: vec![],
                affected_domains: vec!["unknown".to_string()],
            });
        }
        
        function_stats
    }
}

/// 主要的增强统计计算函数
pub async fn compute_enhanced_stats(cve_id: &str) -> Result<()> {
    let mut analyzer = EnhancedStatsAnalyzer::new();
    analyzer.load_analysis_results(cve_id).await?;
    
    let stats = analyzer.generate_enhanced_stats(cve_id).await?;
    
    // 写入JSON文件
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analysis_results");
    let json_path = dir.join(format!("enhanced-stats-{}.json", cve_id));
    let json_content = serde_json::to_string_pretty(&stats)?;
    tokio_fs::write(&json_path, json_content).await?;
    
    // 生成详细的Markdown报告
    let md_content = generate_detailed_report(&stats);
    let md_path = dir.join(format!("enhanced-stats-{}.md", cve_id));
    tokio_fs::write(&md_path, md_content).await?;
    
    tracing::info!("Enhanced stats written: {:?}, {:?}", json_path, md_path);
    Ok(())
}

/// 生成详细的Markdown报告
fn generate_detailed_report(stats: &EnhancedGlobalStats) -> String {
    let mut md = String::new();
    
    md.push_str(&format!("# Enhanced Analysis Report for {}\n\n", stats.cve_id));
    md.push_str(&format!("Generated at: {}\n\n", stats.analysis_timestamp));
    
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!("- **Total Affected Packages**: {}\n", stats.total_packages));
    md.push_str(&format!("- **Direct Impact**: {} packages\n", stats.impact_scope.direct_affected_packages));
    md.push_str(&format!("- **Indirect Impact**: {} packages\n", stats.impact_scope.indirect_affected_packages));
    md.push_str(&format!("- **Maximum Propagation Depth**: {}\n", stats.impact_scope.max_propagation_depth));
    md.push_str(&format!("- **Average Propagation Depth**: {:.2}\n", stats.impact_scope.avg_propagation_depth));
    
    md.push_str("\n## Dependency Layer Analysis\n\n");
    md.push_str("| Layer | Package Count | Function Calls | Impact Level |\n");
    md.push_str("|-------|---------------|----------------|-------------|\n");
    for layer in &stats.dependency_layers {
        let impact_level = match layer.layer {
            0 => "Critical",
            1 => "High", 
            2 => "Medium",
            _ => "Low",
        };
        md.push_str(&format!("| {} | {} | {} | {} |\n", 
                           layer.layer, layer.package_count, 
                           layer.function_call_count, impact_level));
    }
    
    md.push_str("\n## Propagation Width by Depth\n\n");
    for (depth, count) in &stats.impact_scope.propagation_width_by_depth {
        md.push_str(&format!("- Depth {}: {} packages\n", depth, count));
    }
    
    md.push_str("\n## Network Topology Analysis\n\n");
    md.push_str(&format!("- **Total Nodes**: {}\n", stats.network_topology.total_nodes));
    md.push_str(&format!("- **Total Edges**: {}\n", stats.network_topology.total_edges));
    md.push_str(&format!("- **Clustering Coefficient**: {:.4}\n", stats.network_topology.clustering_coefficient));
    
    md.push_str("\n### Hub Packages (Top 5)\n\n");
    for (i, (package, centrality)) in stats.network_topology.hub_packages.iter().take(5).enumerate() {
        md.push_str(&format!("{}. **{}:{}** (centrality: {:.4})\n", 
                           i + 1, package.name, package.version, centrality));
    }
    
    md.push_str("\n## Critical Propagation Paths\n\n");
    for (i, path) in stats.critical_paths.iter().take(10).enumerate() {
        md.push_str(&format!("### Path {} (Depth: {})\n", i + 1, path.total_depth));
        md.push_str(&format!("**{}:{}** → **{}:{}**\n\n", 
                           path.source.name, path.source.version,
                           path.target.name, path.target.version));
        
        for (j, node) in path.path.iter().enumerate() {
            let prefix = if j == 0 { "🔴" } else { "📦" };
            md.push_str(&format!("{}. {} {}:{}\n", j + 1, prefix, 
                               node.package.name, node.package.version));
        }
        md.push_str("\n");
    }
    
    md
}
