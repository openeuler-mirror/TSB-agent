#!/bin/bash
#
# ============================================================
# virtrustd-service.sh - libvirtrustd systemd 管理脚本
#
# 功能：安装、卸载、启动、停止、重启、查看 libvirtrustd 服务
#
# 用法: ./virtrustd-service.sh {install|uninstall|start|stop|restart|reload|status|logs|enable|disable|help}
#
# 示例:
#   ./virtrustd-service.sh install    # 仅在非 RPM 部署中安装服务单元，不自动启用或启动
#   ./virtrustd-service.sh start      # 启动服务
#   ./virtrustd-service.sh status     # 查看状态
#   ./virtrustd-service.sh restart    # 重启服务
#   ./virtrustd-service.sh logs 100   # 查看最近100行日志
#
# ============================================================

# set -e: 任何命令失败（返回非0）时立即退出脚本
set -e

# ============================================================
# 变量定义
# ============================================================

# 服务名称（与 systemd service 文件中的名称一致）
SERVICE_NAME="libvirtrustd"

# 脚本与 RPM 使用相同的系统服务单元目标。
SERVICE_FILE="/usr/lib/systemd/system/${SERVICE_NAME}.service"

# 从脚本所在目录读取唯一的服务单元模板，不依赖当前工作目录。
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
UNIT_TEMPLATE="${SCRIPT_DIR}/${SERVICE_NAME}.service"

# 旧版脚本创建的高优先级单元只由管理员人工迁移。
LEGACY_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# 标识脚本安装的单元，防止卸载来源不明的文件。
SCRIPT_UNIT_MARKER="# virtrustd-service.sh 管理的服务单元"

# 可执行文件路径
BINARY_PATH="/usr/bin/${SERVICE_NAME}"

# 依赖动态库路径
SHARED_LIB_PATH="/usr/lib64/libvirtrust-shared.so"

# 配置文件目录
CONFIG_DIR="/etc/virtrust/config.json"

# ============================================================
# 颜色定义（用于终端输出美观）
# ============================================================
COLOR_RED='\033[0;31m'      # 红色 - 错误
COLOR_GREEN='\033[0;32m'    # 绿色 - 成功
COLOR_YELLOW='\033[0;33m'   # 黄色 - 警告
COLOR_BLUE='\033[0;34m'     # 蓝色 - 信息
COLOR_NC='\033[0m'          # 无颜色 - 重置

# ============================================================
# 日志函数
# 使用颜色输出不同级别的日志，便于用户识别
# ============================================================

# 信息日志（蓝色）
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"
}

# 成功日志（绿色）
log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} $1"
}

# 警告日志（黄色）
log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC} $1"
}

# 错误日志（红色）
log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1"
}

# ============================================================
# 辅助检查函数
# ============================================================

# 检查是否为 root 用户
# systemd 服务管理需要 root 权限
check_root() {
    # EUID 是当前用户的有效用户ID，0 表示 root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_error "Please run: sudo $0 $1"
        exit 1
    fi
}

# 在修改服务前确认 RPM 数据库可查询，且 TSB-agent 包未安装。
check_rpm_unit_ownership() {
    if ! command -v rpm >/dev/null 2>&1; then
        log_error "Cannot determine service unit ownership: rpm is unavailable." >&2
        return 1
    fi

    local package_names=""
    if ! package_names=$(rpm -qa --qf '%{NAME}\n'); then
        log_error "Cannot determine service unit ownership: RPM package query failed." >&2
        return 1
    fi
    if [[ $'\n'"${package_names}"$'\n' == *$'\nTSB-agent\n'* ]]; then
        log_error "Service unit is managed by RPM package TSB-agent; use RPM to update or remove it." >&2
        return 1
    fi

    # 从 RPM 文件清单查询所有者；即使目标文件已被手工删除也不能由脚本接管。
    local -a query_status=()
    if rpm -qa --qf '[%{FILENAMES}\n]' | grep -F -x -- "$SERVICE_FILE" >/dev/null; then
        log_error "Service unit path is owned by an RPM package; use RPM to update or remove it." >&2
        return 1
    else
        query_status=("${PIPESTATUS[@]}")
        if [[ ${query_status[0]} -ne 0 || ${query_status[1]} -ne 1 ]]; then
            log_error "Cannot determine service unit ownership: RPM file query failed." >&2
            return 1
        fi
    fi
    return 0
}

# 旧 /etc 单元会覆盖 /usr/lib 单元，不能在其存在时报告安装成功或执行卸载。
check_legacy_unit_absent() {
    if [[ -e "$LEGACY_SERVICE_FILE" || -L "$LEGACY_SERVICE_FILE" ]]; then
        log_error "A legacy service unit exists: ${LEGACY_SERVICE_FILE}; inspect and migrate it manually." >&2
        return 1
    fi
}

# 只接管带脚本标记的普通文件；无标记文件可能由管理员管理。
check_script_managed_unit() {
    if [[ -L "$SERVICE_FILE" || ! -f "$SERVICE_FILE" ]]; then
        log_error "Service unit is not a script-managed regular file: ${SERVICE_FILE}" >&2
        return 1
    fi
    local first_line=""
    if ! IFS= read -r first_line < "$SERVICE_FILE" || [[ "$first_line" != "$SCRIPT_UNIT_MARKER" ]]; then
        log_error "Service unit is not script-managed: ${SERVICE_FILE}" >&2
        return 1
    fi
}

# 安装只可新建目标或替换已有的脚本单元；调用者需先核验 RPM 所有权。
check_install_unit_target() {
    if [[ -L "$SERVICE_FILE" || ( -e "$SERVICE_FILE" && ! -f "$SERVICE_FILE" ) ]]; then
        log_error "Installation aborted: service unit path must be a regular file or absent: ${SERVICE_FILE}" >&2
        return 1
    fi
    if [[ -f "$SERVICE_FILE" ]]; then
        check_script_managed_unit || return 1
    fi
}

# 有状态命令按单元名作用于当前生效的配置，必须确认它就是脚本将要管理的目标。
# 空路径仅允许首次安装；查询失败或其他目录中的同名单元均由管理员人工处理。
check_effective_unit_source() {
    local fragment=""
    if ! fragment=$(systemctl show "${SERVICE_NAME}" -p FragmentPath --value); then
        log_error "Cannot determine effective service unit: systemctl show failed." >&2
        return 1
    fi
    if [[ -f "$SERVICE_FILE" && "$fragment" == "$SERVICE_FILE" ]] ||
       [[ ! -f "$SERVICE_FILE" && -z "$fragment" ]]; then
        return 0
    fi
    log_error "Effective service unit differs from the script-managed target (effective: ${fragment:-<none>}; target: ${SERVICE_FILE}). Inspect it manually." >&2
    return 1
}

# 检查可执行文件是否存在
# 在启动/重启服务前必须确认文件已安装
check_pre_installation() {
    if [[ ! -f "${BINARY_PATH}" ]]; then
        log_error "Binary not found: ${BINARY_PATH}"
        log_error "Please install the package first"
        log_error "Expected location: ${BINARY_PATH}"
        exit 1
    fi
    if [[ ! -f "${SHARED_LIB_PATH}" ]]; then
        log_error "Shared library not found: ${SHARED_LIB_PATH}"
        log_error "Please install the package first"
        log_error "Expected location: ${SHARED_LIB_PATH}"
        exit 1
    fi
    if [[ ! -f "${CONFIG_DIR}" ]]; then
        log_error "Config file not found: ${CONFIG_DIR}"
        log_error "Please install the package first"
        log_error "Expected location: ${CONFIG_DIR}"
        exit 1
    fi
}

# ============================================================
# 服务安装函数
# 功能：创建 systemd unit 文件
# ============================================================
# 使用子 Shell 限定退出清理的作用域，避免覆盖调用者的 trap。
install_service() (
    log_info "Installing ${SERVICE_NAME} systemd service..."

    # 必须以 root 权限运行
    check_root
    check_rpm_unit_ownership || return 1
    check_legacy_unit_absent || return 1

    # /run/virtrust 由守护进程启动时创建并校验，避免这里受 umask 影响创建不合规目录。
    # 已有目录不自动修改权限；属主或权限不符合要求时，由管理员核验处理。

    # 不自动覆盖链接、目录或来源不明的单元；管理员须先核验其用途。
    check_install_unit_target || return 1
    check_effective_unit_source || return 1
    if [[ -L "$UNIT_TEMPLATE" || ! -f "$UNIT_TEMPLATE" ]]; then
        log_error "Installation aborted: service unit template must be a regular file: ${UNIT_TEMPLATE}" >&2
        return 1
    fi

    # 同目录暂存使最终重命名位于同一文件系统，写入失败不会截断原单元。
    local unit_tmp=""
    local prepare_result=0
    unit_tmp=$(mktemp "${SERVICE_FILE}.tmp.XXXXXX") || prepare_result=$?
    if [[ $prepare_result -ne 0 ]]; then
        log_error "Installation aborted: failed to create a temporary service unit (exit code ${prepare_result})." >&2
        return "$prepare_result"
    fi
    # 正常退出或已捕获失败时清理暂存文件；SIGKILL、断电无法由退出钩子处理。
    trap 'if [[ -n "$unit_tmp" ]]; then rm -f -- "$unit_tmp" || log_warn "Failed to remove temporary service unit: $unit_tmp" >&2; fi' EXIT

    # 先写入来源标记和唯一模板，准备成功后才停止已有服务。
    { printf '%s\n' "$SCRIPT_UNIT_MARKER" && cat -- "$UNIT_TEMPLATE"; } > "$unit_tmp" || prepare_result=$?
    if [[ $prepare_result -ne 0 ]]; then
        log_error "Installation aborted: failed to write the temporary service unit (exit code ${prepare_result}); the service unit was not replaced." >&2
        return "$prepare_result"
    fi

    # 644: root 可读写，其他人可读；权限准备失败时保留原单元。
    chmod 644 "$unit_tmp" || prepare_result=$?
    if [[ $prepare_result -ne 0 ]]; then
        log_error "Installation aborted: failed to set temporary service unit permissions (exit code ${prepare_result})." >&2
        return "$prepare_result"
    fi

    if [[ -f "${SERVICE_FILE}" ]]; then
        log_warn "Service file already exists; stopping the service before replacement..."
        local stop_result=0
        systemctl stop "${SERVICE_NAME}" || stop_result=$?
        if [[ $stop_result -ne 0 ]]; then
            log_error "Installation aborted: failed to stop ${SERVICE_NAME} (exit code ${stop_result}); the service unit was not replaced." >&2
            return "$stop_result"
        fi
    fi

    # stop 期间目标或 RPM 数据库可能变化；发布前重新核验以缩短竞态窗口。
    if ! check_rpm_unit_ownership || ! check_legacy_unit_absent ||
       ! check_install_unit_target || ! check_effective_unit_source; then
        log_error "Installation aborted: service unit ownership or target changed before replacement; check the service state." >&2
        return 1
    fi

    # 以完整文件替换目标；该步骤不保证断电持久性或整个安装流程的原子性。
    local replace_result=0
    mv -T -- "$unit_tmp" "$SERVICE_FILE" || replace_result=$?
    if [[ $replace_result -ne 0 ]]; then
        log_error "Installation aborted: failed to replace the service unit (exit code ${replace_result}); check the service state before retrying." >&2
        return "$replace_result"
    fi
    unit_tmp=""

    # 文件已发布后，加载失败不能再声称原单元未改变，也不自动启动服务。
    local reload_result=0
    systemctl daemon-reload || reload_result=$?
    if [[ $reload_result -ne 0 ]]; then
        log_error "Service unit was updated, but daemon-reload failed (exit code ${reload_result}); check the installed unit and service state." >&2
        return "$reload_result"
    fi

    # 安装时不自动启用开机自启；需要时由管理员显式执行 enable。
    # enable 只注册开机自启，不会立即启动服务。
    #systemctl enable ${SERVICE_NAME}

    log_success "Service installed successfully"
    log_info "Use 'systemctl start ${SERVICE_NAME}' to start the service"
    log_info "Or use: $0 start"
)

# ============================================================
# 服务卸载函数
# 功能：停止服务、禁用开机自启、删除 service 文件
# ============================================================
uninstall_service() {
    log_info "Uninstalling ${SERVICE_NAME} systemd service..."

    check_root
    check_rpm_unit_ownership || return 1
    check_legacy_unit_absent || return 1
    check_script_managed_unit || return 1
    check_effective_unit_source || return 1

    # 直接以停止命令的结果为准，避免把状态查询失败当成无需停止。
    local stop_result=0
    log_info "Stopping service..."
    systemctl stop "${SERVICE_NAME}" || stop_result=$?
    if [[ $stop_result -ne 0 ]]; then
        log_error "Uninstallation aborted: failed to stop ${SERVICE_NAME} (exit code ${stop_result}); the service unit file was not removed." >&2
        return "$stop_result"
    fi

    # stop 后若另一个管理者接管单元，不再继续禁用服务。
    if ! check_rpm_unit_ownership || ! check_legacy_unit_absent ||
       ! check_script_managed_unit || ! check_effective_unit_source; then
        log_error "Uninstallation aborted: service unit ownership or target changed after stop; check the service state." >&2
        return 1
    fi

    # 停止成功后再禁用；失败时保留单元，已执行的停止动作不自动回滚。
    local disable_result=0
    log_info "Disabling service..."
    systemctl disable "${SERVICE_NAME}" || disable_result=$?
    if [[ $disable_result -ne 0 ]]; then
        log_error "Uninstallation aborted: failed to disable ${SERVICE_NAME} (exit code ${disable_result}); the service unit file was not removed. Check the service state." >&2
        return "$disable_result"
    fi

    # disable 期间也可能发生替换；删除前再核验一次。
    if ! check_rpm_unit_ownership || ! check_legacy_unit_absent ||
       ! check_script_managed_unit || ! check_effective_unit_source; then
        log_error "Uninstallation aborted: service unit ownership or target changed before removal; check the service state." >&2
        return 1
    fi

    # 只删除脚本管理的单元路径；保留删除失败的原始诊断和返回码。
    local remove_result=0
    rm -f -- "${SERVICE_FILE}" || remove_result=$?
    if [[ $remove_result -ne 0 ]]; then
        log_error "Uninstallation aborted: failed to remove service unit file ${SERVICE_FILE} (exit code ${remove_result}). Check the file and service state." >&2
        return "$remove_result"
    fi

    # 文件已经删除，重载失败时明确告知实际阶段，不声称卸载已全部完成。
    local reload_result=0
    systemctl daemon-reload || reload_result=$?
    if [[ $reload_result -ne 0 ]]; then
        log_error "Service unit file was removed, but daemon-reload failed (exit code ${reload_result}); check the effective unit and service state." >&2
        return "$reload_result"
    fi

    log_success "Service uninstalled successfully"
}

# ============================================================
# 服务启动函数
# ============================================================
start_service() {
    log_info "Starting ${SERVICE_NAME}..."
    check_pre_installation
    systemctl start ${SERVICE_NAME}
    sleep 1  # 延迟后查看状态，不保证服务已完成初始化或可以处理请求。
    status_service  # 显示启动后的状态
}

# ============================================================
# 服务停止函数
# ============================================================
stop_service() {
    log_info "Stopping ${SERVICE_NAME}..."
    systemctl stop ${SERVICE_NAME}
    log_success "Service stopped"
}

# ============================================================
# 服务重启函数
# 相当于 stop + start 的组合
# ============================================================
restart_service() {
    log_info "Restarting ${SERVICE_NAME}..."
    check_pre_installation
    systemctl restart ${SERVICE_NAME}
    sleep 1  # 延迟后查看状态，不保证服务已完成初始化或可以处理请求。
    status_service  # 显示重启后的状态
}

# ============================================================
# 拒绝未实现的配置重载，不发送信号或自动重启服务。
# 修改配置后，须先确认无在途业务，再由管理员执行受控重启。
# ============================================================
reload_service() {
    log_error "Configuration reload is not supported. Confirm there are no in-flight operations before a controlled restart." >&2
    return 1
}

# ============================================================
# 服务状态查看函数
# 显示服务状态、进程信息、最近日志
# ============================================================
status_service() {
    echo ""
    echo "=============================================="
    echo "  ${SERVICE_NAME} Service Status"
    echo "=============================================="
    echo ""

    # 检查服务是否运行中
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        echo -e "Status: ${COLOR_GREEN}running${COLOR_NC}"
    else
        echo -e "Status: ${COLOR_RED}inactive or status query failed${COLOR_NC}"
    fi

    echo ""

    # 显示 systemd 提供的详细状态信息
    # --no-pager: 不使用分页器，直接输出所有内容
    # 保存主查询结果；非零状态不应阻止后续诊断，也不能被辅助命令覆盖。
    local status_result=0
    systemctl status ${SERVICE_NAME} --no-pager || status_result=$?

    echo ""
    echo "----------------------------------------------"
    echo "  Process Information"
    echo "----------------------------------------------"
    echo ""

    # 获取主进程 PID
    # systemctl show 返回属性值，-p 指定属性名，--value 只返回值
    local pid=""
    local pid_query_ok=1
    if ! pid=$(systemctl show ${SERVICE_NAME} -p MainPID --value); then
        pid_query_ok=0
        log_warn "Failed to query the main process ID" >&2
    fi

    # 区分查询失败、有效非零数字 PID、零值及异常输出。
    if [[ $pid_query_ok -eq 0 ]]; then
        echo "PID: unavailable (query failed)"
    elif [[ "${pid}" =~ ^[0-9]+$ && "${pid}" != "0" ]]; then
        echo "PID: ${pid}"
        echo ""

        # ps 命令显示进程详细信息：
        # - pid: 进程ID
        # - ppid: 父进程ID
        # - cmd: 完整的命令行
        # - etime: 进程运行时间
        # - vsz: 虚拟内存大小（KB）
        # - rss: 实际物理内存大小（KB）
        ps -p "${pid}" -o pid,ppid,cmd,etime,vsz,rss --no-headers || \
            log_warn "Failed to read process information; the process may have exited" >&2
    elif [[ "${pid}" != "0" ]]; then
        echo "PID: unavailable (unexpected query output)"
        log_warn "Main process ID query returned an invalid value" >&2
    else
        echo "PID: N/A (process not running)"
    fi

    echo ""
    echo "----------------------------------------------"
    echo "  Recent Logs (last 10 lines)"
    echo "----------------------------------------------"
    echo ""

    # 显示最近的 journal 日志
    # -u: 按单元（服务）过滤
    # -n: 显示最近N行
    # --no-pager: 不分页
    journalctl -u ${SERVICE_NAME} -n 10 --no-pager || \
        log_warn "Failed to query recent logs" >&2

    echo ""
    echo "=============================================="
    return "$status_result"
}

# ============================================================
# 日志查看函数
# 实时显示服务日志（类似 tail -f）
# ============================================================
show_logs() {
    # 缺省读取 50 行；显式传入的值必须是单个正十进制整数。
    local lines=${1-50}
    if [[ ! "$lines" =~ ^[1-9][0-9]*$ ]]; then
        log_error "Invalid log line count: expected a positive decimal integer." >&2
        return 1
    fi

    echo ""
    echo "----------------------------------------------"
    echo "  Logs (last ${lines} lines, Ctrl+C to exit)"
    echo "----------------------------------------------"
    echo ""

    # journalctl 参数说明：
    # -f: 实时跟踪（follow）新日志
    # -n: 显示最近N行
    # --no-pager: 不分页
    journalctl -u "${SERVICE_NAME}" -n "${lines}" --no-pager -f
}

# ============================================================
# 帮助信息函数
# ============================================================
show_help() {
    cat << EOF
virtrustd-service.sh - ${SERVICE_NAME} systemd management script

Usage: $0 <command>

Commands:
    install      Install a non-RPM service unit without enabling or starting it
    uninstall    Stop, disable, and remove only a script-managed service unit
    start        Start the service
    stop         Stop the service
    restart      Stop then start the service
    reload       Unsupported; returns an error without changing the service
    status       Show service status, process info, and recent logs
    logs [n]     Follow logs; n is one positive decimal integer (default: 50)
    enable       Enable service to start on boot
    disable      Disable service from starting on boot
    help         Show this help message

Examples:
    # Install only when the service unit is not managed by RPM
    sudo $0 install

    # Start the service
    sudo $0 start

    # Check status
    sudo $0 status

    # View last 100 log lines and follow new logs
    sudo $0 logs 100

    # Restart service
    sudo $0 restart

    # Uninstall service
    sudo $0 uninstall

Systemd Direct Commands:
    systemctl start libvirtrustd
    systemctl stop libvirtrustd
    systemctl restart libvirtrustd
    systemctl status libvirtrustd
    journalctl -u libvirtrustd -f      # follow logs
    journalctl -u libvirtrustd -n 100 # last 100 lines

EOF
}

# ============================================================
# 服务启用函数（开机自启）
# ============================================================
enable_service() {
    log_info "Enabling ${SERVICE_NAME} to start on boot..."
    systemctl enable ${SERVICE_NAME}
    log_success "Service enabled"
}

# ============================================================
# 服务禁用函数（取消开机自启）
# ============================================================
disable_service() {
    log_info "Disabling ${SERVICE_NAME} from starting on boot..."
    systemctl disable ${SERVICE_NAME}
    log_success "Service disabled"
}

# ============================================================
# 主入口 - 命令分发
# 根据用户输入的命令调用相应的函数
# ============================================================
case "$1" in
    # 安装服务
    install)
        install_service
        ;;
    # 卸载服务
    uninstall)
        uninstall_service
        ;;
    # 启动服务
    start)
        start_service
        ;;
    # 停止服务
    stop)
        stop_service
        ;;
    # 重启服务
    restart)
        restart_service
        ;;
    # 拒绝不受支持的配置重载
    reload)
        reload_service
        ;;
    # 查看状态
    status)
        status_service
        ;;
    # 查看日志
    logs)
        if [[ $# -gt 2 ]]; then
            log_error "Invalid log line count: expected a single positive decimal integer." >&2
            exit 1
        fi
        show_logs "${2-50}"
        ;;
    # 启用开机自启
    enable)
        enable_service
        ;;
    # 禁用开机自启
    disable)
        disable_service
        ;;
    # 显示帮助
    help|--help|-h)
        show_help
        ;;
    *)
        # 未知命令
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
