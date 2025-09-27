# CVE Tracker 4 Rust - Docker 使用指南

## 快速开始

### 1. 配置数据库连接
先导入crates.io上dump的数据库，我们需要确保 `.env` 文件包含正确的PostgreSQL配置：

```bash
PG_HOST=localhost:5432
PG_USER=postgres
PG_PASSWORD=123
PG_DATABASE=crates_io
```
网址：https://crates.io/data-access#database-dumps

### 2. 测试数据库连接
通过下面命令查看crates_io数据库是否成功部署
```bash
./run-docker.sh test-db
```

### 3. 构建镜像
```bash
./run-docker.sh build
```

### 4. 运行分析
```bash
# 查看帮助
./run-docker.sh run cvetracker4rs --help

# 从CSV文件运行分析
./run-docker.sh run run_from_csv /app/csv/merged.csv

# 运行统计工具
./run-docker.sh run stats --help

# 运行调用图分析
./run-docker.sh run callgraph4rs --help
```

### 3. 查看结果
分析结果会保存在以下目录中（自动映射到主机）：
- `./analysis_results/` - 分析结果
- `./logs/` - 日志文件
- `./data/downloads/` - 下载的文件
- `./data/working/` - 工作目录

## 数据库配置

### 连接主机PostgreSQL
Docker容器配置为连接主机上的PostgreSQL数据库：

- 使用 `host` 网络模式，容器可以直接访问主机的localhost
- 数据库配置通过 `.env` 文件管理
- 支持的环境变量：
  - `PG_HOST`: 数据库主机和端口 (默认: localhost:5432)
  - `PG_USER`: 数据库用户名 (默认: postgres)
  - `PG_PASSWORD`: 数据库密码 (默认: 123)
  - `PG_DATABASE`: 数据库名称 (默认: crates_io)

### 测试连接
```bash
# 测试数据库连接
./run-docker.sh test-db
```

## 资源限制

Docker容器配置了以下资源限制：
- **CPU**: 最多使用 2 个核心
- **内存**: 最多使用 4GB，保留 1GB

配置说明：
- `cpus: 2.0` - 限制容器最多使用2个CPU核心
- `mem_limit: 4g` - 限制容器最多使用4GB内存
- `mem_reservation: 1g` - 为容器保留1GB内存（优先保证）

可以在 `docker-compose.yml` 中修改这些限制。

> **注意**: docker-compose 不支持 CPU 保留设置，只有内存支持保留配置。

## 常用命令

### 构建和运行
```bash
# 构建镜像
./run-docker.sh build

# 运行主程序
./run-docker.sh run cvetracker4rs [参数...]

# 从CSV运行
./run-docker.sh run run_from_csv [参数...]

# 运行统计
./run-docker.sh run stats [参数...]
```

### 调试和维护
```bash
# 测试数据库连接
./run-docker.sh test-db

# 进入容器shell
./run-docker.sh shell

# 查看日志
./run-docker.sh logs

# 停止容器
./run-docker.sh stop

# 清理所有容器和镜像
./run-docker.sh clean
```

## 目录映射

| 容器内路径 | 主机路径 | 说明 |
|-----------|----------|------|
| `/app/analysis_results` | `./analysis_results` | 分析结果输出 |
| `/app/logs` | `./logs` | 日志文件 |
| `/data/downloads` | `./data/downloads` | 下载目录 |
| `/data/working` | `./data/working` | 工作目录 |
| `/app/csv` | `./csv` | CSV输入文件（只读） |

## 环境变量

容器中设置了以下环境变量：
- `RUST_LOG=info` - 日志级别
- `DOWNLOAD_DIR=/data/downloads` - 下载目录
- `WORKING_DIR=/data/working` - 工作目录

## 故障排除

### 1. 构建失败
- 确保 `callgraph4rs` 子模块已正确初始化
- 检查网络连接，确保可以下载依赖

### 2. 权限问题
- 确保运行脚本有执行权限：`chmod +x run-docker.sh`
- 检查目录权限，确保Docker可以访问

### 3. 资源不足
- 调整 `docker-compose.yml` 中的资源限制
- 监控系统资源使用情况

## 高级用法

### 直接使用 docker-compose
```bash
# 构建
docker-compose build

# 运行特定命令
docker-compose run --rm cvetracker4rs run_from_csv --input /app/csv/merged.csv

# 后台运行
docker-compose up -d
```

### 自定义配置
编辑 `docker-compose.yml` 文件来：
- 调整资源限制
- 修改端口映射
- 添加环境变量
- 配置网络设置