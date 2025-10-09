#!/bin/bash

# Add Rust libraries to the dynamic linker path for tools like cg4rs
export LD_LIBRARY_PATH=$(rustc --print sysroot)/lib:$LD_LIBRARY_PATH

# 修复卷映射目录的权限
echo "正在修复目录权限..."

# 如果目录存在且当前用户有权限，则修复权限
if [ -d "/app/logs" ]; then
    sudo chown -R appuser:appuser /app/logs 2>/dev/null || true
fi

if [ -d "/app/analysis_results" ]; then
    sudo chown -R appuser:appuser /app/analysis_results 2>/dev/null || true
fi

if [ -d "/app/logs_cg4rs" ]; then
    sudo chown -R appuser:appuser /app/logs_cg4rs 2>/dev/null || true
fi

if [ -d "/data" ]; then
    sudo chown -R appuser:appuser /data 2>/dev/null || true
fi

echo "权限修复完成"

# 执行传入的命令
exec "$@"