#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 各失败点仅影响临时目录；替代服务命令，验证文件发布前后的状态边界。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir
for scenario in create write marker_write permissions stop replace reload success fresh symlink directory template_missing template_symlink cleanup; do
    export scenario
    mkdir "$test_dir/$scenario"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        if [[ "$scenario" == fresh ]]; then
            rm -- "$SERVICE_FILE"
        fi
        if [[ "$scenario" == symlink ]]; then
            mv "$SERVICE_FILE" "$test_dir/$scenario/original"
            ln -s original "$SERVICE_FILE"
        fi
        if [[ "$scenario" == directory ]]; then
            rm -- "$SERVICE_FILE"
            mkdir "$SERVICE_FILE"
            printf "%s\n" DIRECTORY_CONTENT > "$SERVICE_FILE/marker"
        fi
        if [[ "$scenario" == template_missing ]]; then
            UNIT_TEMPLATE="$test_dir/$scenario/missing.service"
        elif [[ "$scenario" == template_symlink ]]; then
            printf "%s\n" TEMPLATE > "$test_dir/$scenario/source.service"
            ln -s source.service "$test_dir/$scenario/template.service"
            UNIT_TEMPLATE="$test_dir/$scenario/template.service"
        fi
        check_root() { :; }
        check_rpm_unit_ownership() { :; }
        mktemp() {
            [[ "$scenario" != create ]] || return 7
            command mktemp "$@"
        }
        cat() {
            if [[ "$scenario" == write || "$scenario" == cleanup ]]; then
                printf "%s\n" PARTIAL_UNIT
                return 7
            fi
            command cat "$@"
        }
        printf() {
            if [[ "$scenario" == marker_write && "${2-}" == "$SCRIPT_UNIT_MARKER" ]]; then
                return 7
            fi
            builtin printf "$@"
        }
        chmod() {
            [[ "$scenario" != permissions ]] || return 7
            command chmod "$@"
        }
        mv() {
            [[ "$scenario" != replace ]] || return 7
            command mv "$@"
        }
        rm() {
            if [[ "$scenario" == cleanup ]]; then
                echo "SIMULATED_CLEANUP_FAILURE" >&2
                return 11
            fi
            command rm "$@"
        }
        systemctl() {
            if [[ "$1" == show ]]; then
                [[ "$scenario" == fresh ]] || printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            printf "%s\n" "$*" >> "$test_dir/$scenario/calls"
            if [[ ( "$scenario" == stop && "$1" == stop ) ||
                  ( "$scenario" == reload && "$1" == daemon-reload ) ]]; then
                echo "SIMULATED_SYSTEMCTL_FAILURE" >&2
                return 7
            fi
            return 0
        }
        # 子 Shell 的清理不能覆盖调用者的退出钩子；失败时也应执行原钩子。
        trap "echo CALLER_EXIT_TRAP" EXIT
        caller_trap=$(trap -p EXIT)
        install_service
        if [[ $(trap -p EXIT) != "$caller_trap" ]]; then
            echo "CALLER_TRAP_CHANGED" >&2
            exit 99
        fi
    ' 2>&1) || result=$?

    unit="$test_dir/$scenario/libvirtrustd.service"
    calls=""
    [[ ! -f "$test_dir/$scenario/calls" ]] || calls=$(<"$test_dir/$scenario/calls")
    if [[ "$output" != *CALLER_EXIT_TRAP* || "$output" == *CALLER_TRAP_CHANGED* ]]; then
        echo "FAIL: caller exit trap was not preserved for $scenario" >&2
        exit 1
    fi
    case "$scenario" in
        success|reload|fresh)
            expected=$'stop libvirtrustd\ndaemon-reload'
            [[ "$scenario" != fresh ]] || expected="daemon-reload"
            if ! grep -q '^ExecStart=/usr/bin/libvirtrustd ' "$unit" ||
                [[ "$calls" != "$expected" || $(stat -c %a "$unit") != 644 ]]; then
                echo "FAIL: published unit or command sequence is incorrect for $scenario" >&2
                exit 1
            fi
            ;;
        directory)
            if [[ ! -d "$unit" || $(<"$unit/marker") != DIRECTORY_CONTENT || -n "$calls" ||
                  "$output" != *"service unit path must be a regular file or absent"* ]]; then
                echo "FAIL: directory target was not preserved and rejected" >&2
                exit 1
            fi
            ;;
        *)
            if [[ $(<"$unit") != $'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT' ]]; then
                echo "FAIL: original unit changed during $scenario failure" >&2
                exit 1
            fi
            expected=""
            [[ "$scenario" != stop && "$scenario" != replace ]] || expected="stop libvirtrustd"
            if [[ "$calls" != "$expected" ]]; then
                echo "FAIL: unexpected service commands during $scenario failure" >&2
                exit 1
            fi
            ;;
    esac
    if [[ "$scenario" == success || "$scenario" == fresh ]]; then
        [[ $result -eq 0 && "$output" == *"Service installed successfully"* ]] || exit 1
    else
        [[ $result -ne 0 && "$output" != *"Service installed successfully"* ]] || exit 1
        if [[ "$scenario" != symlink && "$scenario" != directory &&
              "$scenario" != template_missing && "$scenario" != template_symlink && $result -ne 7 ]]; then
            echo "FAIL: original error code lost for $scenario" >&2
            exit 1
        fi
    fi
    if [[ "$scenario" == reload && "$output" != *"Service unit was updated, but daemon-reload failed"* ]]; then
        echo "FAIL: reload failure did not explain the published unit state" >&2
        exit 1
    fi
    if [[ "$scenario" == symlink && ! -L "$unit" ]]; then
        echo "FAIL: existing symbolic link was replaced" >&2
        exit 1
    fi
    # 覆盖正常退出和已捕获失败的清理，不模拟 SIGKILL 或断电。
    if [[ "$scenario" == cleanup ]]; then
        if ! compgen -G "$unit.tmp.*" >/dev/null ||
            [[ "$output" != *SIMULATED_CLEANUP_FAILURE* ||
               "$output" != *"Failed to remove temporary service unit: $unit.tmp."* ]]; then
            echo "FAIL: cleanup failure did not report the remaining temporary file" >&2
            exit 1
        fi
        # 故障注入只作用于子进程；最外层夹具退出时清理此处验证过的残留。
    elif compgen -G "$unit.tmp.*" >/dev/null; then
        echo "FAIL: temporary unit remains after $scenario" >&2
        exit 1
    fi
done
echo "PASS: all fourteen unit publication scenarios and caller trap preservation"
