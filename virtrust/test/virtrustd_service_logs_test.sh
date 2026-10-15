#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 隔离 journalctl，核对行数参数不会被拆分、展开或错误转发。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
journalctl() {
    printf 'JOURNAL_ARGUMENT:<%s>\n' "$@"
}
export -f journalctl

for scenario in default valid whitespace wildcard negative zero empty option leading_zero extra; do
    result=0
    case "$scenario" in
        default) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs 2>&1) || result=$? ;;
        valid) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs 10 2>&1) || result=$? ;;
        whitespace) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs '10 20' 2>&1) || result=$? ;;
        wildcard) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs '*' 2>&1) || result=$? ;;
        negative) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs -1 2>&1) || result=$? ;;
        zero) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs 0 2>&1) || result=$? ;;
        empty) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs '' 2>&1) || result=$? ;;
        option) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs --since 2>&1) || result=$? ;;
        leading_zero) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs 01 2>&1) || result=$? ;;
        extra) output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" logs 10 20 2>&1) || result=$? ;;
    esac
    if [[ "$scenario" == default || "$scenario" == valid ]]; then
        expected=50
        [[ "$scenario" != valid ]] || expected=10
        if [[ $result -ne 0 || "$output" != *"JOURNAL_ARGUMENT:<${expected}>"* ||
              "$output" != *"Logs (last ${expected} lines"* ]]; then
            echo "FAIL: $scenario did not pass the expected line count" >&2
            exit 1
        fi
    elif [[ $result -eq 0 || "$output" == *JOURNAL_ARGUMENT* || "$output" != *"Invalid log line count"* ]]; then
        echo "FAIL: invalid input $scenario was not rejected before journalctl" >&2
        exit 1
    fi
done
echo "PASS: all ten log count scenarios"
