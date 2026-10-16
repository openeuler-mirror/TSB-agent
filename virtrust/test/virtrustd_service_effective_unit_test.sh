#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 使用临时路径模拟更高优先级的单元，不访问或修改真实 systemd。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir

for scenario in install_existing install_fresh uninstall_existing show_failure; do
    export scenario
    mkdir -p "$test_dir/$scenario/run/systemd/system"
    printf '%s\n' FOREIGN_UNIT > "$test_dir/$scenario/run/systemd/system/libvirtrustd.service"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        if [[ "$scenario" != install_fresh ]]; then
            printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        fi
        check_root() { :; }
        check_rpm_unit_ownership() { :; }
        systemctl() {
            if [[ "$1" == show ]]; then
                [[ "$*" == "show libvirtrustd -p FragmentPath --value" ]] || return 9
                if [[ "$scenario" == show_failure ]]; then
                    return 7
                fi
                printf "%s\n" "$test_dir/$scenario/run/systemd/system/libvirtrustd.service"
                return 0
            fi
            printf "%s\n" "$*" >> "$test_dir/$scenario/side_effects"
            return 0
        }
        if [[ "$scenario" == uninstall_existing ]]; then
            uninstall_service
        else
            install_service
        fi
    ' 2>&1) || result=$?

    if [[ $result -eq 0 || -e "$test_dir/$scenario/side_effects" ]] ||
       compgen -G "$test_dir/$scenario/libvirtrustd.service.tmp.*" >/dev/null; then
        echo "FAIL: $scenario did not reject an unknown effective unit before side effects" >&2
        exit 1
    fi
    if [[ "$scenario" == install_fresh ]]; then
        [[ ! -e "$test_dir/$scenario/libvirtrustd.service" ]] || exit 1
    elif [[ $(<"$test_dir/$scenario/libvirtrustd.service") != $'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT' ]]; then
        echo "FAIL: $scenario changed the script-owned unit" >&2
        exit 1
    fi
    if [[ "$scenario" == show_failure ]]; then
        [[ "$output" == *"Cannot determine effective service unit"* ]] || exit 1
    else
        [[ "$output" == *"Effective service unit differs"* ]] || exit 1
    fi
done

# 预检查通过后若生效主单元被其他特权管理者切换，后续发布或删除也必须中止。
for scenario in install_switch uninstall_switch; do
    export scenario
    mkdir -p "$test_dir/$scenario/run/systemd/system"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        check_root() { :; }
        check_rpm_unit_ownership() { :; }
        shadowed=0
        systemctl() {
            if [[ "$1" == show ]]; then
                [[ "$*" == "show libvirtrustd -p FragmentPath --value" ]] || return 9
                if [[ $shadowed -eq 0 ]]; then
                    printf "%s\n" "$SERVICE_FILE"
                else
                    printf "%s\n" "$test_dir/$scenario/run/systemd/system/libvirtrustd.service"
                fi
                return 0
            fi
            printf "%s\n" "$*" >> "$test_dir/$scenario/side_effects"
            if [[ ( "$scenario" == install_switch && "$1" == stop ) ||
                  ( "$scenario" == uninstall_switch && "$1" == disable ) ]]; then
                shadowed=1
            fi
            return 0
        }
        if [[ "$scenario" == install_switch ]]; then
            install_service
        else
            uninstall_service
        fi
    ' 2>&1) || result=$?
    expected="stop libvirtrustd"
    [[ "$scenario" != uninstall_switch ]] || expected+=$'\n''disable libvirtrustd'
    original_unit=$'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT'
    if [[ $result -eq 0 || $(<"$test_dir/$scenario/libvirtrustd.service") != "$original_unit" ||
          $(<"$test_dir/$scenario/side_effects") != "$expected" ||
          "$output" != *"Effective service unit differs"* ]]; then
        echo "FAIL: $scenario continued after the effective unit changed" >&2
        exit 1
    fi
done
echo "PASS: shadowed, switched, and unqueryable effective units are rejected"
