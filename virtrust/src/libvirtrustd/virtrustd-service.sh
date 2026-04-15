#!/bin/bash
#
# ============================================================
# virtrustd-service.sh - libvirtrustd systemd 管理脚本
#
# 功能：安装、卸载、启动、停止、重启、查看 libvirtrustd 服务
#
# 用法: ./virtrustd-service.sh {install|uninstall|start|stop|restart|status|logs|enable|disable}
#
# 示例:
#   ./virtrustd-service.sh install    # 安装并启用服务
#   ./virtrustd-service.sh start      # 启动服务
#   ./virtrustd-service.sh status     # 查看状态
#   ./virtrustd-service.sh restart    # 重启服务
#   ./virtrustd-service.sh logs 100   # 查看最近100行日志
#
# ============================================================

# set -e: 任何命令失败（返回非0）时立即退出脚本
# set -e: Exit immediately if a command fails
set -e

# ============================================================
# 变量定义
# ============================================================

# 服务名称（与 systemd service 文件中的名称一致）
SERVICE_NAME="libvirtrustd"

# systemd service 文件路径
# /etc/systemd/system/ 是用户自定义 service 的标准位置
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# 可执行文件路径
BINARY_PATH="/usr/bin/${SERVICE_NAME}"

# 依赖动态库路径
SHARED_LIB_PATH="/usr/lib64/libvirtrust-shared.so"

# 配置文件目录
CONFIG_DIR="/etc/virtrust/config.json"

# 运行时数据目录（PID文件、socket等）
DATA_DIR="/var/run/virtrust"

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
# 功能：创建服务所需的目录和 systemd unit 文件
# ============================================================
install_service() {
    log_info "Installing ${SERVICE_NAME} systemd service..."

    # 必须以 root 权限运行
    check_root

    # 创建服务所需的目录结构
    mkdir -p ${DATA_DIR}     # 运行时数据目录

    # 如果 service 文件已存在，先停止现有服务
    if [[ -f "${SERVICE_FILE}" ]]; then
        log_warn "Service file already exists, overwriting..."
        # 2>/dev/null: 抑制错误输出（如果服务未运行会有错误）
        # || true: 即使前面的命令失败也让脚本继续执行
        systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    fi

    # 使用 heredoc 创建 service 文件
    # 'EOF' 使用单引号可以防止变量被 bash 展开
    cat > ${SERVICE_FILE} << 'EOF'
[Unit]
Description=Virtrust Daemon Service
Documentation=https://gitee.com/openeuler/TSB-agent/virtrust/docs/004-virtrustd.md
After=network.target libvirtd.service
Wants=libvirtd.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/libvirtrustd --config /etc/virtrust/config.json
Restart=on-failure
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -SIGTERM $MAINPID
RestartSec=5s
TimeoutStartSec=30
TimeoutStopSec=30
#ReadWritePaths=/etc/virtrust /var/log/virtrust /var/run
ProtectSystem=false
ProtectHome=false
PrivateTmp=false
LimitNOFILE=65536
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=libvirtrustd
NoNewPrivileges=true
Environment="TSB_AGENT_SO_MODE=mock"
Environment="LOG_LEVEL=info"

[Install]
WantedBy=multi-user.target
EOF

    # 设置 service 文件权限
    # 644: root 可读写，其他人可读（符合 systemd 要求）
    chmod 644 ${SERVICE_FILE}

    # 通知 systemd 重新加载单元文件
    # 在添加、修改、删除 service 文件后必须执行
    systemctl daemon-reload

    # daemon-reexec 会重新执行 systemd 主进程
    # 用于应用某些需要 systemd 本身重启才能生效的配置
    systemctl daemon-reexec

    # 启用服务（创建符号链接实现开机自启）
    # 这不会启动服务，只是注册为开机启动
    #systemctl enable ${SERVICE_NAME}

    log_success "Service installed successfully"
    log_info "Use 'systemctl start ${SERVICE_NAME}' to start the service"
    log_info "Or use: $0 start"
}

# ============================================================
# 服务卸载函数
# 功能：停止服务、禁用开机自启、删除 service 文件
# ============================================================
uninstall_service() {
    log_info "Uninstalling ${SERVICE_NAME} systemd service..."

    check_root

    # 检查服务是否正在运行，如果运行则停止
    # is-active --quiet: 只返回退出码，不输出信息
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        log_info "Stopping service..."
        systemctl stop ${SERVICE_NAME}
    fi

    # 检查服务是否已启用（开机自启）
    # 如果是则取消启用
    if systemctl is-enabled --quiet ${SERVICE_NAME}; then
        log_info "Disabling service..."
        systemctl disable ${SERVICE_NAME}
    fi

    # 删除 service 文件
    rm -f ${SERVICE_FILE}

    # 重新加载 systemd 配置
    systemctl daemon-reload
    systemctl daemon-reexec

    log_success "Service uninstalled successfully"
}

# ============================================================
# 服务启动函数
# ============================================================
start_service() {
    log_info "Starting ${SERVICE_NAME}..."
    check_pre_installation
    systemctl start ${SERVICE_NAME}
    sleep 1  # 等待1秒让服务完全启动
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
    sleep 1  # 等待1秒让服务完全启动
    status_service  # 显示重启后的状态
}

# ============================================================
# 配置重载函数
# 发送 SIGHUP 信号让进程优雅重启（重新读取配置文件）
# 与 restart 的区别：restart 会完全停止再启动，reload 只重载配置
# ============================================================
reload_service() {
    log_info "Reloading ${SERVICE_NAME} configuration..."
    systemctl reload ${SERVICE_NAME}
    log_success "Configuration reloaded"
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
        echo -e "Status: ${COLOR_RED}stopped${COLOR_NC}"
    fi

    echo ""

    # 显示 systemd 提供的详细状态信息
    # --no-pager: 不使用分页器，直接输出所有内容
    systemctl status ${SERVICE_NAME} --no-pager

    echo ""
    echo "----------------------------------------------"
    echo "  Process Information"
    echo "----------------------------------------------"
    echo ""

    # 获取主进程 PID
    # systemctl show 返回属性值，-p 指定属性名，--value 只返回值
    local pid=$(systemctl show ${SERVICE_NAME} -p MainPID --value 2>/dev/null || echo "0")

    # 检查 PID 是否有效（非0、非空）
    if [[ "${pid}" != "0" && -n "${pid}" ]]; then
        echo "PID: ${pid}"
        echo ""

        # ps 命令显示进程详细信息：
        # - pid: 进程ID
        # - ppid: 父进程ID
        # - cmd: 完整的命令行
        # - etime: 进程运行时间
        # - vsz: 虚拟内存大小（KB）
        # - rss: 实际物理内存大小（KB）
        ps -p ${pid} -o pid,ppid,cmd,etime,vsz,rss --no-headers 2>/dev/null || true
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
    journalctl -u ${SERVICE_NAME} -n 10 --no-pager 2>/dev/null || echo "No logs available"

    echo ""
    echo "=============================================="
}

# ============================================================
# 日志查看函数
# 实时显示服务日志（类似 tail -f）
# ============================================================
show_logs() {
    # $1 是第一个参数（行数），默认为 50
    local lines=${1:-50}

    echo ""
    echo "----------------------------------------------"
    echo "  Logs (last ${lines} lines, Ctrl+C to exit)"
    echo "----------------------------------------------"
    echo ""

    # journalctl 参数说明：
    # -f: 实时跟踪（follow）新日志
    # -n: 显示最近N行
    # --no-pager: 不分页
    journalctl -u ${SERVICE_NAME} -n ${lines} --no-pager -f
}

# ============================================================
# 帮助信息函数
# ============================================================
show_help() {
    cat << EOF
virtrustd-service.sh - ${SERVICE_NAME} systemd management script

Usage: $0 <command>

Commands:
    install      Install and enable the service (start on boot)
    uninstall    Stop service, disable, and remove service file
    start        Start the service
    stop         Stop the service
    restart      Stop then start the service
    reload       Send SIGHUP to reload configuration (graceful)
    status       Show service status, process info, and recent logs
    logs [n]     Show and follow last n lines of logs (default: 50)
    enable       Enable service to start on boot
    disable      Disable service from starting on boot
    help         Show this help message

Examples:
    # Install and enable service
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
    # 重载配置
    reload)
        reload_service
        ;;
    # 查看状态
    status)
        status_service
        ;;
    # 查看日志
    logs)
        show_logs ${2:-50}
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