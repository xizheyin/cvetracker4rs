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

### 准备 crates.io 数据库（必需）

本项目依赖于一个包含了 crates.io 完整数据的 PostgreSQL 数据库。我们强烈推荐使用项目提供的 Docker 脚本来自动完成所有设置。

#### 方式一：一键自动部署（推荐）

这是最简单、最快捷的方式。你只需要一个能正常工作的 Docker 环境。

1.  **确保 Docker 和 Docker Compose 已安装**。
2.  **执行一键部署脚本**：
    ```bash
    ./run-docker.sh db-oneclick
    ```

这个命令会自动完成以下所有工作：
- 下载官方的 crates.io 数据库快照到 `./data/cratesio_dump/db-dump.tar.gz`（如果本地没有的话）。
- 解压缩数据到 `./data/cratesio_dump/` 目录。
- 启动一个 PostgreSQL 数据库容器（docker-compose.yml中的postgres服务）。
- 自动创建数据库表结构并导入所有数据（scripts/init-cratesio.sh）。
- 等待导入完成后给出成功提示。

**注意**：首次执行时，数据导入过程会非常耗时（可能需要30分钟到数小时，取决于你的网络和磁盘性能），请耐心等待脚本执行完成。
**tips**: 我们可以把import.sql中只保留crates、versions、dependencies这三张表的导入语句，其他表的导入语句可以注释掉。这样可以节省大量时间

导入过程输出的log是这样：
```bash
rust@rust-PowerEdge-R750xs:/mnt/shixin/cvetracker4rs$ ./run-docker.sh db-oneclick
[INFO] 创建必要的目录...
[SUCCESS] 目录创建完成
[WARNING] 将清理旧容器与数据卷，确保执行全新导入（postgres_data 将被删除）。
[+] Running 2/2
 ✔ Container cratesio-db               Removed                                                                           0.1s 
 ✔ Volume cvetracker4rs_postgres_data  Removed                                                                           0.5s 
[INFO] 检测到已存在的 dump 压缩包，跳过下载: ./data/db-dump.tar.gz
[INFO] 检测到 ./data/cratesio_dump 已存在且非空，跳过解压步骤
[INFO] 启动 Postgres 并自动执行初始化脚本导入...
[+] Running 3/3
 ✔ Volume cvetracker4rs_postgres_data                                  Created                                           0.0s 
 ✔ Container cratesio-db                                               Started                                           0.2s 
 ! postgres Published ports are discarded when using host network mode                                                   0.0s 
[INFO] 等待导入完成（检测日志标记）...
[SUCCESS] 数据库导入完成！
[INFO] 验证数据库连接...
              now              
-------------------------------
 2025-09-29 08:38:52.429571+00
(1 row)

[SUCCESS] 一键导入完成。
```

#### 方式二：使用 Docker 分步操作

如果你已经手动下载了数据库快照，或者想要对流程有更多控制，可以使用以下命令。

1.  **准备数据**：
    - 下载 [crates.io 数据库快照](https://static.crates.io/db-dump.tar.gz) 并将其命名为 `db-dump.tar.gz` 放在 `./data/` 目录下。
    - 解压它到 `./data/cratesio_dump/` 目录。（这时你也可以参考上面的tips来注释掉不需要的表的导入语句）

2.  **启动数据库服务**：
    ```bash
    ./run-docker.sh db-up
    ```
    首次启动时，脚本会自动导入位于 `./data/cratesio_dump/` 下的数据。你可以使用 `docker compose logs -f postgres` 来观察导入进度。

3.  **管理数据库**：
    - **停止服务**：`./run-docker.sh db-down`
    - **重置数据库**（删除所有数据并重新导入）：`./run-docker.sh db-reset`

---

<details>
<summary><b>附：手动设置数据库（不使用 Docker）</b></summary>

如果你不希望使用 Docker，也可以手动设置数据库。

1) **安装 PostgreSQL**（建议版本 17）

2) **创建用户与数据库**（示例）
   ```bash
   # 使用 postgres 超级用户创建
   psql -h localhost -U postgres -c "CREATE ROLE rust LOGIN PASSWORD 'rust';"
   psql -h localhost -U postgres -c "CREATE DATABASE crates_io_db OWNER rust;"
   ```

3) **下载并解压 crates.io 数据库 dump**
   - 从 [官方快照](https://static.crates.io/db-dump.tar.gz) 获取 dump 压缩包。
   - 解压后，你会得到 `schema.sql`, `import.sql` 和一个 `data/` 目录。

4) **恢复 dump 到数据库**
   - **第一步：创建表结构**
     ```bash
     psql -h localhost -U rust -d crates_io_db -f path/to/schema.sql
     ```
   - **第二步：导入数据**（仍然可以注释掉不必要的表的导入语句）
     ```bash
     # 这个脚本会从其所在目录的相对路径 data/ 中加载 CSV 文件
     cd path/to/
     psql -h localhost -U rust -d crates_io_db -f import.sql
     ```

5) **配置 .env 文件**
   确保 `.env` 文件中的数据库连接信息与你手动创建的一致。
   ```bash
   PG_HOST=localhost:5432
   PG_USER=rust
   PG_PASSWORD=rust
   PG_DATABASE=crates_io_db
   ```
</details>



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


