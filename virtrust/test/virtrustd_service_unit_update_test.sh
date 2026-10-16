#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 真实函数仅操作临时单元；隔离 systemctl，不访问系统服务。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir

# RPM 与脚本必须从同一模板安装同权限的单元。
if ! awk '
    $1 == "install" && $2 == "-m" && $3 == "644" &&
    $4 == "%{root_dir}/src/libvirtrustd/libvirtrustd.service" &&
    $5 == "%{buildroot}%{_unitdir}/libvirtrustd.service" { found = 1 }
    END { exit !found }
' "$test_root/rpm/TSB-agent.spec"; then
    echo "FAIL: RPM service unit source, destination, or permissions differ from the script" >&2
    exit 1
fi

# 缺省目标与 RPM 一致；旧 /etc 路径仅用于拒绝遗留覆盖。
if ! bash -c '
    source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
    [[ "$SERVICE_FILE" == /usr/lib/systemd/system/libvirtrustd.service &&
       "$LEGACY_SERVICE_FILE" == /etc/systemd/system/libvirtrustd.service &&
       "$UNIT_TEMPLATE" == "$test_root/src/libvirtrustd/libvirtrustd.service" ]]
'; then
    echo "FAIL: default service paths or template path are incorrect" >&2
    exit 1
fi

for operation in install uninstall; do
    export operation
    bash -c '
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
            printf "%s\n" "$*" >> "$test_dir/$operation.calls"
            return 0
        }
        # 在其他工作目录调用，验证模板是按脚本位置而不是 cwd 定位的。
        cd "$test_dir"
        "${operation}_service"
    ' >"$test_dir/$operation.output" 2>&1

    if grep -q '^daemon-reexec$' "$test_dir/$operation.calls"; then
        echo "FAIL: $operation reexecuted the service manager" >&2
        exit 1
    fi
    if [[ "$operation" == install ]]; then
        expected=$'stop libvirtrustd\ndaemon-reload'
        if [[ $(head -n 1 "$test_dir/libvirtrustd.service") != "# virtrustd-service.sh 管理的服务单元" ]] ||
            ! tail -n +2 "$test_dir/libvirtrustd.service" |
                cmp -s - "$test_root/src/libvirtrustd/libvirtrustd.service"; then
            echo "FAIL: installation did not use the canonical service unit template" >&2
            exit 1
        fi
    else
        expected=$'stop libvirtrustd\ndisable libvirtrustd\ndaemon-reload'
        if [[ -e "$test_dir/libvirtrustd.service" ]]; then
            echo "FAIL: uninstallation did not remove the service unit" >&2
            exit 1
        fi
    fi
    if [[ $(<"$test_dir/$operation.calls") != "$expected" ]]; then
        echo "FAIL: unexpected service command sequence for $operation" >&2
        exit 1
    fi
done
echo "PASS: installation and uninstallation reload units without manager reexecution"
