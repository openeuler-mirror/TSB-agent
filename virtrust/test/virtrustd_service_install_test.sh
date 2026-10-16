#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 仅在临时目录验证安装流程；替代权限检查和服务命令，不修改系统单元。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir

# 独立进程保持生产脚本的 set -e 语义，不把安装函数放入条件表达式。
result=0
output=$(bash -c '
    source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
    SERVICE_FILE="$test_dir/libvirtrustd.service"
    LEGACY_SERVICE_FILE="$test_dir/legacy.service"
    printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
    check_root() { :; }
    check_rpm_unit_ownership() { :; }
    systemctl() {
        if [[ "$1" == show ]]; then
            printf "%s\n" "$SERVICE_FILE"
            return 0
        fi
        printf "%s\n" "$*" >> "$test_dir/calls"
        if [[ "$1" == stop ]]; then
            echo "SIMULATED_STOP_FAILURE" >&2
            return 7
        fi
    }
    install_service
' 2>&1) || result=$?

if [[ $result -ne 7 ]]; then
    echo "FAIL: installation did not preserve the stop failure code" >&2
    exit 1
fi
if [[ $(<"$test_dir/libvirtrustd.service") != $'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT' ]]; then
    echo "FAIL: installation overwrote the existing unit" >&2
    exit 1
fi
if [[ $(<"$test_dir/calls") != "stop libvirtrustd" ]]; then
    echo "FAIL: installation invoked commands after stop failed" >&2
    exit 1
fi
if [[ "$output" != *SIMULATED_STOP_FAILURE* || "$output" != *"Installation aborted"* || "$output" == *"Service installed successfully"* ]]; then
    echo "FAIL: installation failure diagnostics are incorrect" >&2
    exit 1
fi
echo "PASS: stop failure prevents unit replacement and further service commands"
