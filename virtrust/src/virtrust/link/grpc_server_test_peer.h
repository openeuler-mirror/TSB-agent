/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#pragma once

#include "virtrust/link/grpc_server.h"

namespace virtrust {
// 在被测对象之后声明，使提前返回时先关闭故障，再析构被测对象。
template <typename Flag> class TestFaultReset {
public:
    explicit TestFaultReset(Flag &flag) : flag_(flag)
    {}
    ~TestFaultReset()
    {
        flag_ = false;
    }
    TestFaultReset(const TestFaultReset &) = delete;
    TestFaultReset &operator=(const TestFaultReset &) = delete;

private:
    Flag &flag_;
};

// 仅供单元测试在启动前替换外部操作；不向生产调用方暴露测试接口。
class GrpcServerTestPeer {
public:
    using StartupResult = GrpcServer::StartupResult;
    static auto &Ops(GrpcServer &server)
    {
        return server.operations_;
    }
    static bool HasService(const GrpcServer &server)
    {
        return server.service_ != nullptr;
    }
    static bool HasServer(const GrpcServer &server)
    {
        return server.server_ != nullptr;
    }
    static bool HasThread(const GrpcServer &server)
    {
        return server.server_thread_ && server.server_thread_->joinable();
    }
    // 仅在启停完成或已同步暂停时查询；与线程是否可 join 分开验证。
    static bool HasThreadObject(const GrpcServer &server)
    {
        return server.server_thread_ != nullptr;
    }
    // 由不持有生命周期锁的测试线程调用；成功时自动释放，不读取受保护资源。
    // try_lock 失败允许是伪失败，不能单独据此证明另一个线程持锁。
    static bool CanAcquireLifecycleLock(GrpcServer &server)
    {
        std::unique_lock<std::mutex> guard(server.lifecycleMutex_, std::try_to_lock);
        return guard.owns_lock();
    }
    static bool HasIdentity(const GrpcServer &server)
    {
        return server.socketIdentityRecorded_;
    }
};
} // 命名空间 virtrust
