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
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose 未安装，请先安装 Docker Compose"
        exit 1
    fi
}

# 创建必要的目录
create_directories() {
    print_info "创建必要的目录..."
    mkdir -p analysis_results logs data/downloads data/working
    print_success "目录创建完成"
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
        docker-compose run --rm cvetracker4rs /bin/bash -c "
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
        docker-compose run $docker_args cvetracker4rs cvetracker4rs --help
    else
        # 运行指定命令
        print_info "运行命令: ${cmd_args[*]}"
        docker-compose run $docker_args cvetracker4rs "${cmd_args[@]}"
    fi
}

# 进入shell
enter_shell() {
    create_directories
    print_info "进入容器 shell..."
    docker-compose run --rm cvetracker4rs /bin/bash
}

# 查看日志
show_logs() {
    docker-compose logs -f cvetracker4rs
}

# 停止容器
stop_containers() {
    print_info "停止容器..."
    docker-compose down
    print_success "容器已停止"
}

# 清理
clean_up() {
    print_warning "这将删除所有相关的容器和镜像，确定要继续吗? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_info "清理容器和镜像..."
        docker-compose down --rmi all --volumes --remove-orphans
        print_success "清理完成"
    else
        print_info "取消清理操作"
    fi
}

# 主逻辑
main() {
    check_docker
    
    case "${1:-help}" in
        "build")
            create_directories
            build_image
            ;;
        "run")
            shift
            run_command "$@"
            ;;
        "shell")
            enter_shell
            ;;
        "logs")
            show_logs
            ;;
        "stop")
            stop_containers
            ;;
        "clean")
            clean_up
            ;;
        "test-db")
            test_database
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            print_error "未知命令: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"