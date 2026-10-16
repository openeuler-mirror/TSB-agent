#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 卸载仅操作临时单元；逐阶段注入失败，验证状态与错误码。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export test_root test_dir
for scenario in stop disable remove reload success; do
    export scenario
    mkdir "$test_dir/$scenario"
    result=0
    output=$(bash -c '
        source "$test_root/src/libvirtrustd/virtrustd-service.sh" help >/dev/null
        SERVICE_FILE="$test_dir/$scenario/libvirtrustd.service"
        LEGACY_SERVICE_FILE="$test_dir/$scenario/legacy.service"
        printf "%s\n" "$SCRIPT_UNIT_MARKER" ORIGINAL_UNIT > "$SERVICE_FILE"
        check_root() { :; }
        check_rpm_unit_ownership() { :; }
        systemctl() {
            if [[ "$1" == show ]]; then
                printf "%s\n" "$SERVICE_FILE"
                return 0
            fi
            printf "%s\n" "$*" >> "$test_dir/$scenario/calls"
            case "$1" in
                is-active|is-enabled) return 1 ;;
                stop)
                    if [[ "$scenario" == stop ]]; then
                        echo "SIMULATED_STOP_ERROR" >&2
                        return 7
                    fi ;;
                disable)
                    if [[ "$scenario" == disable ]]; then
                        echo "SIMULATED_DISABLE_ERROR" >&2
                        return 8
                    fi ;;
                daemon-reload)
                    if [[ "$scenario" == reload ]]; then
                        echo "SIMULATED_RELOAD_ERROR" >&2
                        return 10
                    fi ;;
                *) return 99 ;;
            esac
            return 0
        }
        rm() {
            printf "%s\n" REMOVE_UNIT >> "$test_dir/$scenario/calls"
            if [[ "$scenario" == remove ]]; then
                echo "SIMULATED_REMOVE_ERROR" >&2
                return 9
            fi
            command rm "$@"
        }
        uninstall_service
    ' 2>&1) || result=$?

    expected_calls="stop libvirtrustd"
    expected_error=SIMULATED_STOP_ERROR
    expected_result=7
    if [[ "$scenario" != stop ]]; then
        expected_calls+=$'\ndisable libvirtrustd'
        expected_error=SIMULATED_DISABLE_ERROR
        expected_result=8
    fi
    if [[ "$scenario" == remove || "$scenario" == reload || "$scenario" == success ]]; then
        expected_calls+=$'\nREMOVE_UNIT'
        expected_error=SIMULATED_REMOVE_ERROR
        expected_result=9
    fi
    if [[ "$scenario" == reload || "$scenario" == success ]]; then
        expected_calls+=$'\ndaemon-reload'
        expected_error=SIMULATED_RELOAD_ERROR
        expected_result=10
        if [[ -e "$test_dir/$scenario/libvirtrustd.service" ]]; then
            echo "FAIL: unit still exists after removal" >&2
            exit 1
        fi
    elif [[ ! -f "$test_dir/$scenario/libvirtrustd.service" ]] ||
        [[ $(<"$test_dir/$scenario/libvirtrustd.service") != $'# virtrustd-service.sh 管理的服务单元\nORIGINAL_UNIT' ]]; then
        echo "FAIL: original unit changed before successful removal" >&2
        exit 1
    fi
    [[ "$scenario" != success ]] || expected_result=0
    if [[ $result -ne $expected_result || $(<"$test_dir/$scenario/calls") != "$expected_calls" ]]; then
        echo "FAIL: incorrect exit code or operation sequence for $scenario" >&2
        exit 1
    fi
    if [[ "$scenario" == success ]]; then
        [[ "$output" == *"Service uninstalled successfully"* ]] || exit 1
    elif [[ "$output" != *"$expected_error"* || "$output" == *"Service uninstalled successfully"* ]]; then
        echo "FAIL: original error was lost or success was reported for $scenario" >&2
        exit 1
    fi
    if [[ "$scenario" == reload && "$output" != *"Service unit file was removed, but daemon-reload failed"* ]]; then
        echo "FAIL: reload failure did not explain that the unit was removed" >&2
        exit 1
    fi
done
echo "PASS: all five uninstall scenarios"
