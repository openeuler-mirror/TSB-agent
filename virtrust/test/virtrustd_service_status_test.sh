#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# 用替代命令隔离真实服务，检查辅助诊断不会覆盖主状态码。
set -eu
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export TEST_PID_OUTPUT=0 TEST_PS_STATUS=0
systemctl() {
    case "$1" in
        is-active) return "$TEST_STATUS" ;;
        status) echo "STATUS_REACHED"; return "$TEST_STATUS" ;;
        show)
            if [[ "$TEST_AUX_FAILURE" == 1 ]]; then
                echo "SIMULATED_SHOW_ERROR" >&2
                return 1
            fi
            printf '%s\n' "$TEST_PID_OUTPUT"
            ;;
        *) return 99 ;;
    esac
}
journalctl() {
    echo "JOURNAL_REACHED"
    if [[ "$TEST_AUX_FAILURE" == 1 ]]; then
        echo "SIMULATED_JOURNAL_ERROR" >&2
        return 1
    fi
}
# 进程信息查询也必须隔离；同时验证 PID 以独立参数传给 ps。
ps() {
    echo "PS_REACHED"
    if [[ $# -ne 5 || "$1" != -p || "$2" != "$TEST_PID_OUTPUT" ||
          "$3" != -o || "$4" != pid,ppid,cmd,etime,vsz,rss || "$5" != --no-headers ]]; then
        echo "UNEXPECTED_PS_ARGUMENTS" >&2
        return 99
    fi
    if [[ "$TEST_PS_STATUS" -ne 0 ]]; then
        echo "SIMULATED_PS_ERROR" >&2
        return "$TEST_PS_STATUS"
    fi
    echo "SIMULATED_PROCESS_INFORMATION"
}
export -f systemctl journalctl ps

# 主状态成功、非活动和查询失败均必须继续日志诊断并保留原返回码。
for TEST_STATUS in 0 3 4; do
    for TEST_AUX_FAILURE in 0 1; do
        export TEST_STATUS TEST_AUX_FAILURE
        result=0
        output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" status 2>&1) || result=$?
        if [[ $result -ne $TEST_STATUS || "$output" != *JOURNAL_REACHED* || "$output" == *PS_REACHED* ]]; then
            echo "FAIL: status=$TEST_STATUS auxiliary_failure=$TEST_AUX_FAILURE result=$result" >&2
            exit 1
        fi
        if [[ "$output" == *stopped* ]]; then
            echo "FAIL: non-active status was classified as stopped" >&2
            exit 1
        fi
        if [[ "$TEST_AUX_FAILURE" == 1 && ( "$output" != *SIMULATED_SHOW_ERROR* || "$output" != *SIMULATED_JOURNAL_ERROR* ) ]]; then
            echo "FAIL: auxiliary diagnostics were suppressed" >&2
            exit 1
        fi
    done
done

# 覆盖非零 PID、进程已退出以及异常查询输出，主状态成功和失败均须保留。
export TEST_AUX_FAILURE=0
for TEST_STATUS in 0 3; do
    export TEST_STATUS
    for scenario in valid_pid ps_failure empty_pid invalid_pid; do
        TEST_PID_OUTPUT=1234
        TEST_PS_STATUS=0
        case "$scenario" in
            ps_failure) TEST_PS_STATUS=8 ;;
            empty_pid) TEST_PID_OUTPUT="" ;;
            invalid_pid) TEST_PID_OUTPUT="invalid pid" ;;
        esac
        export TEST_PID_OUTPUT TEST_PS_STATUS
        result=0
        output=$(bash "$test_root/src/libvirtrustd/virtrustd-service.sh" status 2>&1) || result=$?
        if [[ $result -ne $TEST_STATUS || "$output" != *JOURNAL_REACHED* || "$output" == *UNEXPECTED_PS_ARGUMENTS* ]]; then
            echo "FAIL: scenario=$scenario status=$TEST_STATUS result=$result" >&2
            exit 1
        fi
        case "$scenario" in
            valid_pid)
                if [[ "$output" != *PS_REACHED* || "$output" != *SIMULATED_PROCESS_INFORMATION* ]]; then
                    echo "FAIL: valid PID did not produce process information" >&2
                    exit 1
                fi
                ;;
            ps_failure)
                if [[ "$output" != *SIMULATED_PS_ERROR* || "$output" != *"Failed to read process information"* ]]; then
                    echo "FAIL: process query failure diagnostics are missing" >&2
                    exit 1
                fi
                ;;
            empty_pid|invalid_pid)
                if [[ "$output" == *PS_REACHED* || "$output" != *"PID: unavailable (unexpected query output)"* ||
                      "$output" != *"Main process ID query returned an invalid value"* ]]; then
                    echo "FAIL: invalid PID was not rejected correctly" >&2
                    exit 1
                fi
                ;;
        esac
    done
done
echo "PASS: all fourteen status diagnostic scenarios"
