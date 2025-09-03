## cvetracker4rs

一个用于追踪 Rust 生态中指定 CVE 在依赖网络中传播影响的分析工具。支持：
- 按命令行参数对单一目标进行分析，并实时显示旋转进度
- 从 CSV 批量读取多个任务并分析，带总进度条与逐项提示
- 汇总分析结果，产出统计 JSON 与 Markdown 报告

### 功能特性
- **依赖回溯与传播分析**：以易受影响的 crate+version 作为起点，沿反向依赖进行 BFS 分析
- **批量任务处理**：从 CSV 读取多条任务，顺序执行并跟踪进度
- **统计汇总**：在 `analysis_results/<CVE>/` 生成 `stats-<CVE>.json` 与 `stats-<CVE>.md`，按 target 函数（`file-content.target`）分组输出每函数的 callers 数、path_constraints 与 path_package_num 的 min/max/avg/分位数（p50/p90/p95/p99）、直方图与 Top 样本
- **日志分离**：控制台与文件同时输出，分析子流程拥有独立日志目录

### 环境依赖

需要连接到 crates.io 数据库的 PostgreSQL（或含相同结构的数据快照）

### 构建
```bash
cargo build --release
```

### 环境变量（可用 `.env` 配置，已启用 dotenv）
可以在项目根目录创建 `.env`：
```bash
# PostgreSQL 连接信息
PG_HOST=localhost:port
PG_USER=XXX
PG_PASSWORD=YYY
PG_DATABASE=NAME

# 工作目录
DOWNLOAD_DIR=XXXX/downloads/
WORKING_DIR=XXXX/downloads/working

# 并发控制（可根据机器调整）
MAX_CONCURRENT_BFS_NODES=32
MAX_CONCURRENT_DEP_DOWNLOAD=32

# 日志等级（可选）
RUST_LOG=info
```

### 目录说明
- `analysis_results/<CVE>/`：该 CVE 的函数调用分析结果与统计报告目录
- `logs/`：主程序日志文件（即当前程序cvetracker或run_from_csv的日志）
- `logs_cg4rs/<cve>_<ts>/`：子程序cg4rs（函数分析、下载、补丁等）日志，这个是按照cve分类的

### 可执行程序与用法

#### 1) 单任务分析：`cvetracker4rs`
带实时旋转进度（spinners）。参数顺序：`<cve_id> <crate_name> <version_range> <target_function_paths>`
```bash
cargo run --bin cvetracker4rs -- \
  CVE-2025-31130 \
  gix-features \
  "<0.41.0" \
  "gix_features::hash::Hasher::digest,gix_features::hash::Hasher::update,gix_features::hash::Write::flush"
```
说明：
- `version_range` 使用 semver 约束表达式（如 `"<0.41.0"`, `">=1, <2"`）
- `target_function_paths` 逗号分隔的完整函数路径列表

#### 2) 批量分析：`run_from_csv`
带总进度条。CSV 列顺序固定：`cve_id,crate_name,version_range,target_function_paths`
```bash
# 默认 CSV 含表头
cargo run --bin run_from_csv -- ./tasks.csv

# 如 CSV 无表头，可显式声明
cargo run --bin run_from_csv -- ./tasks_no_header.csv --has-header=false
```
CSV 示例（含表头）：
```csv
cve_id,crate_name,version_range,target_function_paths
CVE-2025-31130,gix-features,<0.41.0,"gix_features::hash::Hasher::digest,gix_features::hash::Hasher::update"
```

#### 3) 仅统计：`stats`
对指定 `CVE` 汇总 `analysis_results/<CVE>/` 下已有的分析结果：
```bash
cargo run --bin stats -- CVE-2025-31130
```

### 进度展示
- `cvetracker4rs`：控制台显示旋转指示器（初始化/分析/统计计算等阶段会更新消息）
- `run_from_csv`：显示总进度条，逐项任务（每个 CSV 行）开始与完成时更新消息

### 输出产物
- `analysis_results/<CVE>/<crate>-<version>.txt`：单个 subject（crate-version）的函数调用分析结果，JSON 数组；每个元素内 `file-content.target` 为被分析的 target 函数路径，`file-content.callers[*]` 含：
  - `path_constraints`：从 target 到 caller 的约束数量
  - `path_package_num`：路径跨越的 package 数量
- `analysis_results/<CVE>/stats-<CVE>.json`：聚合统计（分 target 函数）。每个函数包含：
  - `total_callers`、`unique_call_paths`
  - path_constraints 的 `min/max/avg` 与分位数 `p50/p90/p95/p99`
  - path_package_num 的 `min/max/avg` 与分位数 `p50/p90/p95/p99`
  - 每函数直方图：`path_constraints_histogram`、`package_hops_histogram`
  - Top 样本：`top_callers_by_constraints`、`top_callers_by_package_hops`（含 subject 与 caller_path）
- `analysis_results/<CVE>/stats-<CVE>.md`：Markdown 摘要（分 target 展示核心指标与直方图/Top 样本）

### 常见问题
- 无法连接数据库：检查 `.env` 中的 `PG_*` 配置与 PostgreSQL 网络连通
- 速度慢或超时：适当调大 `MAX_CONCURRENT_*`，但注意磁盘与网络带宽瓶颈
- 分析结果为空：确认 `version_range` 与 `target_function_paths` 是否正确，且目标版本确实存在
- 调试日志：设置 `RUST_LOG=debug` 或 `trace` 获得更详细输出

### 许可证
MIT


