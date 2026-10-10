/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <sys/types.h>

#include <functional>
#include <utility>

#include "virtrust/base/process_file_lock.h"
#include "virtrust/link/grpc_server.h"

namespace virtrust {
// 守护进程实例资格；必须先取得资格再创建服务，且比服务更晚析构。
// 目录和所有者由启动代码固定指定，配置文件不提供覆盖入口。
// 同一对象的获取、诊断读取和销毁须由调用方串行执行。
class DaemonInstance {
public:
    // 创建/校验私有目录后尝试独占加锁；不会修改已有目录权限。
    LockOutcome Acquire(const std::string &directory, uid_t owner);
    // 仅描述最近一次 Acquire 的失败原因，不代表业务迁移错误。
    int LastErrno() const noexcept
    {
        return error_;
    }
    // 带失败步骤、路径和 errno 的诊断；引用有效期不超过本对象生命周期。
    const std::string &LastError() const noexcept
    {
        return detail_;
    }

private:
    LockOutcome Fail(const std::string &path, const char *step, int error);
    // 实例锁不会因 VIRTRUST_MOCK 被替换为模拟锁。
    ProcessFileLock lock_;
    int error_ = 0;
    std::string detail_;
};

// 启动编排：实例资格先于 Socket 操作，服务关闭并销毁后才释放资格。
// 路径/所有者参数用于受信部署与隔离测试，生产入口只传固定常量。
// 仅供单线程编排；Start、Stop、RunUntilStopped、LastError、析构不能并发调用。
// 内层 GrpcServer 的互斥锁不意味着本类线程安全。
class DaemonRuntime {
public:
    DaemonRuntime(LinkConfig config, std::string directory, uid_t owner)
        : directory_(std::move(directory)), owner_(owner), server_(std::move(config))
    {}
    LockOutcome Start() noexcept;
    // 停止未完成时保留实例资格；仅路径残留时可以释放，后续仍可重试路径清理。
    StopResult Stop() noexcept;
    // 沿用一秒检查周期；运行故障或回收失败返回非零，不自动重启。
    // Shutdown、join 等仍可能长期阻塞，未实现强制超时退出。
    int RunUntilStopped(const std::function<bool()> &stopRequested) noexcept;
    const std::string &LastError() const noexcept
    {
        return error_;
    }

private:
    friend class DaemonRuntimeTestPeer;
    // 生产入口固定为 /run/virtrust，测试使用独立临时目录。
    std::string directory_;
    // 生产入口固定为 root；不读取用户配置。
    uid_t owner_;
    std::string error_;
    // 成员按声明逆序析构，server_ 必须排在 instance_ 后面。
    DaemonInstance instance_;
    GrpcServer server_;
};
} // 命名空间 virtrust
