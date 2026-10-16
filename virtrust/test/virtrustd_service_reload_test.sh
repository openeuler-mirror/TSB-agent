#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 隔离服务管理命令，验证拒绝重载不会影响真实系统服务。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
systemctl() {
    echo "UNEXPECTED_SYSTEMCTL_CALL: $*"
    return 0
}
export -f systemctl

# 在独立 Bash 中执行真实命令入口；允许捕获预期的非零退出码。
result=0
output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" reload 2>&1) || result=$?
if [[ "$output" == *UNEXPECTED_SYSTEMCTL_CALL* ]]; then
    echo "FAIL: reload invoked systemctl" >&2
    exit 1
fi
if [[ $result -eq 0 || "$output" != *"Configuration reload is not supported"* ]]; then
    echo "FAIL: reload did not report an unsupported operation" >&2
    exit 1
fi
if [[ "$output" == *"Configuration reloaded"* ]]; then
    echo "FAIL: reload reported success" >&2
    exit 1
fi

# 两种部署来源都不得声明未实现的重载命令。
if grep -Eq '^[[:space:]]*ExecReload=' \
    "$test_root/src/libvirtrustd/libvirtrustd.service" \
    "$test_root/src/libvirtrustd/virtrustd-service.sh"; then
    echo "FAIL: service definition still declares ExecReload" >&2
    exit 1
fi
echo "PASS: unsupported reload is rejected without systemctl"
