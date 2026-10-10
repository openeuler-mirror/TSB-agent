/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <fmt/format.h>
#include <getopt.h>
#include <unistd.h>

#include <csignal>

#include "libvirtrustd/daemon_instance.h"
#include "libvirtrustd/defines.h"
#include "libvirtrustd/utils.h"

#include "virtrust/base/logger.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_server.h"

namespace virtrust {
namespace {
volatile sig_atomic_t g_stopFlag = 0;

void SignalHandler(int signum)
{
    VIRTRUST_LOG_INFO("Received signal: {}", signum);
    if (signum == SIGPIPE) {
        VIRTRUST_LOG_INFO("SIGPIPE signal received, ignored.");

        return;
    }
    g_stopFlag = 1;
}

void PrintVersion(std::string_view progname)
{
    fmt::print("{} version: {}\n", progname, LIBVIRTRUSTD_VERSION);
}

void PrintUsage(std::string_view progname)
{
    fmt::print("\n"
               "  USAGE:\n"
               "    {} <args> [options]\n"
               "\n"
               "  REQUIRED ARGS:\n"
               "    --config           path to config file\n"
               "\n"
               "  OPTIONS:\n"
               "    -d | --debug       run in debug mode\n"
               "    --help             print this help\n"
               "    --version          show version\n"
               "\n",
               progname);
}

int ProcessArgs(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    std::vector<option> opt = {
        {"config", required_argument, nullptr, 'c'},
        {"debug", no_argument, nullptr, 'd'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0},
    };

    std::string configPath;
    // 开头的 + 禁止重排参数；c 后的冒号表示该选项需要参数，由 optarg 接收。
    while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'c':
                configPath = std::string(optarg);
                break;
            case 'd':
                virtrust::Logger::Instance()->SetDisplayLogLevel(virtrust::LogLevel::DEBUG);
                break;
            case 'v':
                PrintVersion(argv[0]);
                return 0; // 成功返回。
            case 'h':
                PrintUsage(argv[0]);
                return 0; // 成功返回。
            case '?':
            default:
                PrintUsage(argv[0]);
                return 1; // 失败返回。
        }
    }

    if (configPath.empty()) {
        fmt::print("\n"
                   "  ERROR: Missing requried config files\n");
        PrintUsage(argv[0]);
        return 1; // 失败返回。
    }

    auto ret = MakeLinkConfigFromJsonFile(configPath);
    if (ret.has_value()) {
        ConfigMgr::Instance().SetLinkConfig(ret.value());
        // 帮助/版本及配置解析不获取资格；任何 Socket 清理或监听之前必须先持实例锁。
        // 此对象先停止并销毁服务，再释放锁，覆盖正常退出和启动失败路径。
        DaemonRuntime runtime(ret.value(), VIRTRUSTD_RUNTIME_DIRECTORY, 0);
        if (runtime.Start() != LockOutcome::Acquired) {
            try {
                fmt::print("Daemon startup failed: {}\n", runtime.LastError());
            } catch (...) {
            }
            return 1;
        }

        const int result = runtime.RunUntilStopped([] { return g_stopFlag != 0; });
        if (result != 0) {
            // 回收已显式执行；输出失败不能妨碍析构兜底或改变失败退出状态。
            try {
                fmt::print("Daemon runtime or cleanup failed: {}\n", runtime.LastError());
            } catch (...) {
            }
        }
        return result;
    } else {
        fmt::print("\n"
                   "  ERROR: Failed to parse config files\n");
        // 通信配置创建失败。
        return 1;
    }
}
} // namespace
} // namespace virtrust

int main(int argc, char **argv)
{
    // 注册信号处理函数。
    signal(SIGINT, virtrust::SignalHandler);
    signal(SIGTERM, virtrust::SignalHandler);
    signal(SIGPIPE, virtrust::SignalHandler);

    auto ret = virtrust::Logger::Instance()->InitLog(static_cast<int>(virtrust::LogLevel::INFO),
                                                     virtrust::VIRTRUSTD_LOGFILE_NAME);
    if (ret != virtrust::VirtrustRc::OK) {
        fmt::print("\nInitLog failed\n");
        return 1;
    }

    return virtrust::ProcessArgs(argc, argv);
}
