#!/bin/bash

# CVE Tracker 4 Rust - Docker 运行脚本
# 使用方法: ./run-docker.sh [command] [args...]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi
    
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose V2 未安装，请先安装 Docker Compose V2（使用 'docker compose'）"
        exit 1
    fi
}

# 创建必要的目录
create_directories() {
    print_info "创建必要的目录..."
    mkdir -p analysis_results logs data/downloads data/working
    print_success "目录创建完成"
}

# 读取 .env
ensure_env() {
    if [ -f ".env" ]; then
        source .env
    else
        print_warning ".env 未找到，使用默认值 PG_HOST=localhost:5432, PG_USER=postgres, PG_PASSWORD=123, PG_DATABASE=crates_io"
        PG_HOST=${PG_HOST:-localhost:5432}
        PG_USER=${PG_USER:-postgres}
        PG_PASSWORD=${PG_PASSWORD:-123}
        PG_DATABASE=${PG_DATABASE:-crates_io}
    fi
}

# 构建Docker镜像
build_image() {
    print_info "构建 Docker 镜像..."
    
    export DOCKER_BUILDKIT=1 
    docker compose build --progress plain
    
    if [ $? -eq 0 ]; then
        print_success "镜像构建完成"
    else
        print_error "镜像构建失败"
        return 1
    fi
}

# 测试数据库连接
test_database() {
    print_info "测试数据库连接..."
    
    # 检查.env文件是否存在
    if [ ! -f ".env" ]; then
        print_error ".env 文件不存在，请先配置数据库连接参数"
        return 1
    fi
    
    # 从.env文件读取数据库配置
    source .env
    
    print_info "数据库配置:"
    echo "  主机: $PG_HOST"
    echo "  用户: $PG_USER"
    echo "  数据库: $PG_DATABASE"
    
    # 使用psql测试连接（如果可用）
    if command -v psql &> /dev/null; then
        print_info "使用 psql 测试连接..."
        PGPASSWORD=$PG_PASSWORD psql -h ${PG_HOST%:*} -p ${PG_HOST#*:} -U $PG_USER -d $PG_DATABASE -c "SELECT version();" 2>/dev/null
        if [ $? -eq 0 ]; then
            print_success "数据库连接测试成功！"
        else
            print_error "数据库连接测试失败，请检查配置和数据库状态"
        fi
    else
        print_warning "psql 未安装，跳过直接连接测试"
        print_info "将在Docker容器中测试连接..."
        
        # 在容器中测试连接
        create_directories
        docker compose run --rm cvetracker4rs /bin/bash -c "
            echo 'Testing database connection...'
            echo 'Host: $PG_HOST'
            echo 'User: $PG_USER'
            echo 'Database: $PG_DATABASE'
        "
    fi
}

# 显示帮助信息
show_help() {
    echo "CVE Tracker 4 Rust - Docker 运行脚本"
    echo ""
    echo "使用方法:"
    echo "  $0 build                    # 构建 Docker 镜像"
    echo "  $0 run [command] [args...]  # 运行指定命令"
    echo "  $0 shell                    # 进入容器 shell"
    echo "  $0 logs                     # 查看容器日志"
    echo "  $0 stop                     # 停止容器"
    echo "  $0 clean                    # 清理容器和镜像"
    echo "  $0 test-db                  # 测试数据库连接"
    echo "  $0 db-up                    # 启动 postgres（若 ./data/cratesio_dump 中已有 dump，首次启动将自动导入）"
    echo "  $0 db-down                  # 直接停止 postgres 服务"
    echo "  $0 db-import                # 在容器内强制执行导入（覆盖风险，谨慎使用；需先准备 ./data/cratesio_dump）"
    echo "  $0 db-reset                 # 删除数据卷并重新初始化（重新导入最新 dump；需先准备 ./data/cratesio_dump）"
    echo "  $0 db-oneclick              # 一键下载并导入 crates.io 数据库（清空旧数据）"

    echo ""
    echo "可用的命令:"
    echo "  cvetracker4rs [args...]     # 主程序"
    echo "  run_from_csv [args...]      # 从CSV运行分析"
    echo "  stats [args...]             # 统计工具"
    echo "  callgraph4rs [args...]      # 调用图分析"
    echo ""
    echo "示例:"
    echo "  $0 run cvetracker4rs --help"
    echo "  $0 run run_from_csv --input /app/csv/merged.csv"
    echo "  $0 run stats --help"
}

# 运行命令
run_command() {
    create_directories
    
    # 检查是否有-it参数
    local docker_args="--rm"
    local cmd_args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -it|--interactive)
                docker_args="$docker_args -it"
                shift
                ;;
            *)
                cmd_args+=("$1")
                shift
                ;;
        esac
    done
    
    if [ ${#cmd_args[@]} -eq 0 ]; then
        # 没有参数，显示帮助
        docker compose run $docker_args cvetracker4rs cvetracker4rs --help
    else
        # 运行指定命令
        print_info "运行命令: ${cmd_args[*]}"
        docker compose run $docker_args cvetracker4rs "${cmd_args[@]}"
    fi
}

# 进入shell
enter_shell() {
    create_directories
    print_info "进入容器 shell..."
    docker compose run --rm cvetracker4rs /bin/bash
}

# 查看日志
show_logs() {
    docker compose logs -f cvetracker4rs
}

# 停止容器
stop_containers() {
    print_info "停止容器..."
    docker compose down
    print_success "容器已停止"
}

# 清理
clean_up() {
    print_warning "这将删除所有相关的容器和镜像，确定要继续吗? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_info "清理容器和镜像..."
        docker compose down --rmi all --volumes --remove-orphans
        print_success "清理完成"
    else
        print_info "取消清理操作"
    fi
}



# 直接启动 postgres（若 ./data/cratesio_dump 已有 dump，首次启动将自动导入）
db_up() {
    create_directories
    print_info "启动 postgres 服务..."
    docker compose up -d postgres
    print_success "服务已启动：postgres"
}

# 直接停止 postgres 服务
db_down() {
    print_info "停止 postgres 服务..."
    docker compose down -v
    print_success "服务已停止：postgres"
}

# 重置数据库（删除数据卷并重新初始化，适合重新导入最新 dump，需先准备 ./data/cratesio_dump）
db_reset() {
    print_warning "将删除 postgres 数据卷并停止服务，所有数据会丢失。确定吗？(y/N)"
    read -r reply
    if [[ ! "$reply" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_info "已取消重置。"
        return 0
    fi
    print_info "停止并删除容器与卷..."
    docker compose down -v
    print_info "重新启动导入流程（首次启动将自动执行初始化脚本）..."
    docker compose up -d postgres
    print_success "已重置并重新启动。请通过 'docker compose logs -f postgres' 观察初始化日志。"
}

# 强制执行导入（适用于已存在数据目录的情况，直接在容器内执行 psql）
db_import() {
    ensure_env
    print_warning "将直接在现有数据库上执行 schema.sql + import.sql，可能覆盖或破坏现有数据，请谨慎！"
    read -p "确定继续执行导入吗？(y/N) " -r reply
    if [[ ! "$reply" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_info "已取消导入。"
        return 0
    fi
    
    print_info "检查 dump 文件是否已下载..."
    docker compose exec -T cratesio-db sh -c 'ls -l /docker-entrypoint-initdb.d/dump/schema.sql /docker-entrypoint-initdb.d/dump/import.sql' || {
        print_error "未找到 dump 文件，请先将 crates.io dump 下载并解压到 ./data/cratesio_dump，或执行: ./run-docker.sh db-oneclick"
        return 1
    }
    
    print_info "开始在容器内执行导入..."
    docker compose exec -T cratesio-db bash -lc "cd /docker-entrypoint-initdb.d/dump && PGPASSWORD='$PG_PASSWORD' psql -v ON_ERROR_STOP=1 -U '$PG_USER' -d '$PG_DATABASE' -f schema.sql"
    docker compose exec -T cratesio-db bash -lc "cd /docker-entrypoint-initdb.d/dump && PGPASSWORD='$PG_PASSWORD' psql -v ON_ERROR_STOP=1 -U '$PG_USER' -d '$PG_DATABASE' -f import.sql"
    docker compose exec -T cratesio-db bash -lc "PGPASSWORD='$PG_PASSWORD' psql -v ON_ERROR_STOP=1 -U '$PG_USER' -d '$PG_DATABASE' -c 'VACUUM ANALYZE;'"
    print_success "导入完成。"
}




# 一键下载并导入 crates.io 数据库（非交互，全新导入）
db_oneclick() {
    check_docker
    ensure_env
    create_directories
    mkdir -p ./data/cratesio_dump

    print_warning "将清理旧容器与数据卷，确保执行全新导入（postgres_data 将被删除）。"
    docker compose down -v || true

    local dump_path="./data/db-dump.tar.gz"
    if [ -s "$dump_path" ]; then
        print_info "检测到已存在的 dump 压缩包，跳过下载: $dump_path"
    else
        print_info "下载 crates.io dump 到: $dump_path"
        if ! curl -L --retry 3 --retry-delay 5 -o "$dump_path" https://static.crates.io/db-dump.tar.gz; then
            print_error "下载失败，请检查网络后重试。"
            return 1
        fi
    fi

    # 如果目录已存在且非空，则跳过解压
    if [ -d ./data/cratesio_dump ] && [ -n "$(ls -A ./data/cratesio_dump 2>/dev/null)" ]; then
        print_info "检测到 ./data/cratesio_dump 已存在且非空，跳过解压步骤"
    else
        print_info "解压 dump 到 ./data/cratesio_dump..."
        if ! tar -xzf "$dump_path" -C ./data/cratesio_dump --strip-components=1; then
            print_error "解压失败，请确认 tar 能解压该文件。"
            return 1
        fi
    fi

    chmod -R a+rX ./data/cratesio_dump

    # 过滤不兼容项：transaction_timeout 参数与 crunchy_pooler 扩展
    if [ -f ./data/cratesio_dump/schema.sql ]; then
        if grep -q "transaction_timeout" ./data/cratesio_dump/schema.sql; then
            print_warning "检测到 schema.sql 中存在 transaction_timeout，执行过滤..."
            sed -i '/transaction_timeout/Id' ./data/cratesio_dump/schema.sql || true
        fi
        if grep -qi "crunchy_pooler" ./data/cratesio_dump/schema.sql; then
            print_warning "检测到 schema.sql 中存在 crunchy_pooler 扩展，执行过滤..."
            sed -i '/crunchy_pooler/Id' ./data/cratesio_dump/schema.sql || true
        fi
        if grep -qi "pgaudit" ./data/cratesio_dump/schema.sql; then
            print_warning "检测到 schema.sql 中存在 pgaudit 扩展，执行过滤..."
            sed -i '/pgaudit/Id' ./data/cratesio_dump/schema.sql || true
        fi
    fi

    print_info "启动 Postgres 并自动执行初始化脚本导入..."
        docker compose up -d postgres

    print_info "等待导入完成（检测日志标记）..."
    # 最长等待 30 分钟（每2秒检查一次）
    local max_checks=900
    local ok=0
    for i in $(seq 1 $max_checks); do
        if docker compose logs --tail=200 postgres | grep -q "\[init-cratesio\] Import completed successfully."; then
            ok=1
            break
        fi
        sleep 2
    done

    if [ "$ok" = "1" ]; then
        print_success "数据库导入完成！"
        print_info "验证数据库连接..."
        if command -v psql &> /dev/null; then
            PGPASSWORD=$PG_PASSWORD psql -h ${PG_HOST%:*} -p ${PG_HOST#*:} -U $PG_USER -d $PG_DATABASE -c "SELECT NOW();" || true
        else
            docker compose exec -T cratesio-db sh -lc "psql -U '$PG_USER' -d '$PG_DATABASE' -c 'SELECT NOW();'" || true
        fi
        print_success "一键导入完成。"
    else
        print_warning "未在预期时间内检测到完成标记，请使用 'docker compose logs -f postgres' 查看导入进度。"
        return 1
    fi
}

# 主逻辑
main() {
    check_docker
    
    case "$1" in
        build)
            build_image ;;
        run)
            shift; run_command "$@" ;;
        shell)
            enter_shell ;;
        logs)
            show_logs ;;
        stop)
            stop_containers ;;
        clean)
            clean_up ;;
        test-db)
            test_database ;;
        db-up)
            db_up ;;
        db-down)
            db_down ;;
        db-reset)
            db_reset ;;
        db-import)
            db_import ;;
        db-oneclick)
            db_oneclick ;;
        *)
            show_help ;;
    esac
}

main "$@"