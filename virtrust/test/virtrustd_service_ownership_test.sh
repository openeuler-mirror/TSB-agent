#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 仅使用临时单元和替代命令，验证 RPM 管理的单元不会被脚本接管。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir

for scenario in package other_owner; do
    export scenario
    mkdir "$test_dir/$scenario"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        printf "%s\n" ORIGINAL_UNIT > "$SERVICE_FILE"
        check_root() { :; }
        rpm() {
            if [[ "$1" == -qa && "$2" == --qf && "$3" == "%{NAME}\\n" ]]; then
                [[ "$scenario" != package ]] || printf "%s\n" TSB-agent
                return 0
            fi
            if [[ "$1" == -qa && "$2" == --qf && "$3" == "[%{FILENAMES}\\n]" ]]; then
                [[ "$scenario" != other_owner ]] || printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            return 99
        }
        systemctl() { printf "%s\n" "$*" >> "$test_dir/$scenario/calls"; }
        install_service
    ' 2>&1) || result=$?

    if [[ $result -eq 0 || -e "$test_dir/$scenario/calls" ||
          $(<"$test_dir/$scenario/libvirtrustd.service") != ORIGINAL_UNIT || "$output" != *"RPM"* ]]; then
        echo "FAIL: RPM ownership did not prevent script unit replacement for $scenario" >&2
        exit 1
    fi
done

# RPM 文件清单中的所有权不依赖文件存在；卸载也必须拒绝其他 RPM 所有者和链接。
for scenario in other_owner_uninstall other_owner_missing_install target_symlink_uninstall; do
    export scenario
    mkdir "$test_dir/$scenario"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        if [[ "$scenario" != other_owner_missing_install ]]; then
            printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        fi
        if [[ "$scenario" == target_symlink_uninstall ]]; then
            mv "$SERVICE_FILE" "$test_dir/$scenario/original"
            ln -s original "$SERVICE_FILE"
        fi
        check_root() { :; }
        rpm() {
            if [[ "$3" == "%{NAME}\\n" ]]; then
                return 0
            fi
            if [[ "$3" == "[%{FILENAMES}\\n]" ]]; then
                [[ "$scenario" == target_symlink_uninstall ]] || printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            return 99
        }
        systemctl() { printf "%s\n" "$*" >> "$test_dir/$scenario/calls"; }
        operation=${scenario##*_}
        "${operation}_service"
    ' 2>&1) || result=$?
    unit="$test_dir/$scenario/libvirtrustd.service"
    if [[ $result -eq 0 || -e "$test_dir/$scenario/calls" ]]; then
        echo "FAIL: $scenario performed a service operation" >&2
        exit 1
    fi
    if [[ "$scenario" == other_owner_missing_install ]]; then
        [[ ! -e "$unit" && "$output" == *"owned by an RPM package"* ]] || exit 1
    elif [[ "$scenario" == target_symlink_uninstall ]]; then
        [[ -L "$unit" && "$output" == *"not a script-managed regular file"* ]] || exit 1
    else
        [[ $(<"$unit") == $'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT' &&
           "$output" == *"owned by an RPM package"* ]] || exit 1
    fi
done

# 模拟有权限的管理者在 stop/disable 期间替换单元；后续操作不得发布或删除新单元。
for scenario in install_rpm_stop install_unknown_stop uninstall_rpm_stop uninstall_unknown_stop uninstall_rpm_disable uninstall_unknown_disable; do
    export scenario
    mkdir "$test_dir/$scenario"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        check_root() { :; }
        rpm_claim=0
        rpm() {
            if [[ "$3" == "%{NAME}\\n" ]]; then
                return 0
            fi
            if [[ "$3" == "[%{FILENAMES}\\n]" ]]; then
                [[ $rpm_claim -eq 0 ]] || printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            return 99
        }
        systemctl() {
            if [[ "$1" == show ]]; then
                printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            printf "%s\n" "$*" >> "$test_dir/$scenario/calls"
            if [[ ( "$scenario" == install_* && "$1" == stop ) ||
                  ( "$scenario" == uninstall_*_stop && "$1" == stop ) ||
                  ( "$scenario" == uninstall_*_disable && "$1" == disable ) ]]; then
                if [[ "$scenario" == *_rpm_* ]]; then
                    rpm_claim=1
                else
                    printf "%s\n" UNKNOWN_REPLACEMENT > "$SERVICE_FILE"
                fi
            fi
        }
        operation=${scenario%%_*}
        "${operation}_service"
    ' 2>&1) || result=$?
    expected_unit=UNKNOWN_REPLACEMENT
    [[ "$scenario" != *_rpm_* ]] || expected_unit=$'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT'
    expected_calls="stop libvirtrustd"
    [[ "$scenario" != uninstall_*_disable ]] || expected_calls+=$'\n''disable libvirtrustd'
    if [[ $result -eq 0 || $(<"$test_dir/$scenario/libvirtrustd.service") != "$expected_unit" ||
          $(<"$test_dir/$scenario/calls") != "$expected_calls" ||
          "$output" == *"successfully"* ]]; then
        echo "FAIL: concurrent replacement was not preserved for $scenario" >&2
        exit 1
    fi
    if [[ "$scenario" == *_rpm_* && "$output" != *"owned by an RPM package"* ]] ||
       [[ "$scenario" == *_unknown_* && "$output" != *"not script-managed"* ]]; then
        echo "FAIL: concurrent replacement did not report its cause for $scenario" >&2
        exit 1
    fi
done

result=0
output=$(bash -c '
    source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
    SERVICE_FILE="$test_dir/uninstall.service"
    LEGACY_SERVICE_FILE="$test_dir/uninstall-legacy.service"
    printf "%s\n" ORIGINAL_UNIT > "$SERVICE_FILE"
    check_root() { :; }
    rpm() {
        [[ "$1" != -qa || "$2" != --qf || "$3" != "%{NAME}\\n" ]] || printf "%s\n" TSB-agent
        return 0
    }
    systemctl() { printf "%s\n" "$*" >> "$test_dir/uninstall.calls"; }
    uninstall_service
' 2>&1) || result=$?
if [[ $result -eq 0 || -e "$test_dir/uninstall.calls" ||
      ! -f "$test_dir/uninstall.service" || $(<"$test_dir/uninstall.service") != ORIGINAL_UNIT ||
      "$output" != *"RPM"* ]]; then
    echo "FAIL: RPM installation did not prevent script unit uninstallation" >&2
    exit 1
fi

# 查询失败与“明确未拥有”不同，安装和卸载都必须在服务操作前退出。
for scenario in name_query_error file_query_error; do
    for operation in install uninstall; do
        export scenario operation
        result=0
        output=$(bash -c '
            source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
            SERVICE_FILE="$test_dir/$scenario-$operation.service"
            LEGACY_SERVICE_FILE="$test_dir/$scenario-$operation-legacy.service"
            printf "%s\n" ORIGINAL_UNIT > "$SERVICE_FILE"
            check_root() { :; }
            rpm() {
                if [[ "$3" == "%{NAME}\\n" && "$scenario" == name_query_error ]]; then
                    return 17
                fi
                if [[ "$3" == "[%{FILENAMES}\\n]" && "$scenario" == file_query_error ]]; then
                    return 18
                fi
                return 0
            }
            systemctl() { printf "%s\n" "$*" >> "$test_dir/$scenario-$operation.calls"; }
            "${operation}_service"
        ' 2>&1) || result=$?
        if [[ $result -eq 0 || -e "$test_dir/$scenario-$operation.calls" ||
              $(<"$test_dir/$scenario-$operation.service") != ORIGINAL_UNIT ||
              "$output" != *"Cannot determine service unit ownership"* ]]; then
            echo "FAIL: $scenario allowed $operation to act on an unknown owner" >&2
            exit 1
        fi
    done
done

for operation in install uninstall; do
    export operation
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/no-rpm-$operation.service"
        LEGACY_SERVICE_FILE="$test_dir/no-rpm-$operation-legacy.service"
        printf "%s\n" ORIGINAL_UNIT > "$SERVICE_FILE"
        check_root() { :; }
        systemctl() { printf "%s\n" "$*" >> "$test_dir/no-rpm-$operation.calls"; }
        PATH="$test_dir/no-such-bin"
        "${operation}_service"
    ' 2>&1) || result=$?
    if [[ $result -eq 0 || -e "$test_dir/no-rpm-$operation.calls" ||
          $(<"$test_dir/no-rpm-$operation.service") != ORIGINAL_UNIT ||
          "$output" != *"rpm is unavailable"* ]]; then
        echo "FAIL: absent rpm command allowed $operation to modify the service" >&2
        exit 1
    fi
done

# 旧 /etc 单元和来源不明的目标不得被新脚本覆盖或删除。
for scenario in legacy_file legacy_symlink unknown_target; do
    for operation in install uninstall; do
        export scenario operation
        result=0
        output=$(bash -c '
            source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
            SERVICE_FILE="$test_dir/$scenario-$operation.service"
            LEGACY_SERVICE_FILE="$test_dir/$scenario-$operation-legacy.service"
            printf "%s\n" ORIGINAL_UNIT > "$SERVICE_FILE"
            if [[ "$scenario" == legacy_file ]]; then
                printf "%s\n" LEGACY_UNIT > "$LEGACY_SERVICE_FILE"
            elif [[ "$scenario" == legacy_symlink ]]; then
                ln -s missing-unit "$LEGACY_SERVICE_FILE"
            fi
            check_root() { :; }
            check_rpm_unit_ownership() { :; }
            systemctl() { printf "%s\n" "$*" >> "$test_dir/$scenario-$operation.calls"; }
            "${operation}_service"
        ' 2>&1) || result=$?
        if [[ $result -eq 0 || -e "$test_dir/$scenario-$operation.calls" ||
              $(<"$test_dir/$scenario-$operation.service") != ORIGINAL_UNIT ]]; then
            echo "FAIL: $scenario allowed $operation to change an unapproved unit" >&2
            exit 1
        fi
        if [[ "$scenario" == legacy_* && "$output" != *"legacy"* ]] ||
           [[ "$scenario" == unknown_target && "$output" != *"script-managed"* ]]; then
            echo "FAIL: $scenario did not explain why $operation was rejected" >&2
            exit 1
        fi
    done
done
echo "PASS: RPM ownership and query failures prevent unsafe service operations"
