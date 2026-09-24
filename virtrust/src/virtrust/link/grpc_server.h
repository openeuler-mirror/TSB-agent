/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <grpcpp/grpcpp.h>
#include <sys/types.h>

#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include "virtrust/link/defines.h"

namespace virtrust {
// 管理同步 gRPC 服务与等待线程；调用方持有节点实例资格后才能启动。
class GrpcServer {
public:
    explicit GrpcServer(LinkConfig config);
    // 析构与主动停止共用回收路径，启动失败也不能遗留 joinable 线程。
    ~GrpcServer();

    // 返回时已取得确定的启动结果，失败时已完成线程回收。
    LinkRc Start();
    // 可重复停止；不设置强制截止时间，避免改变在途业务语义。
    void Stop();
    // 返回最近一次启动结果的诊断副本。
    std::string LastError() const;

private:
    void RunServer(std::promise<std::string> ready);
    bool PrepareSocket();
    void StopUnlocked();

    LinkConfig config_;
    // 串行化 Start/Stop；工作线程不获取此锁，避免等待启动结果或 join 时死锁。
    mutable std::mutex lifecycleMutex_;
    std::string lastError_;
    // 仅清理本次创建的 Socket，不按路径盲删后来替换的文件。
    dev_t socketDevice_ = 0;
    ino_t socketInode_ = 0;
    bool ownsSocket_ = false;

    std::unique_ptr<grpc::Server> server_;
    std::unique_ptr<std::thread> server_thread_;
};
} // namespace virtrust
