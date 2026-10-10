/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <grpcpp/grpcpp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include "virtrust/link/defines.h"

namespace virtrust {
class MigrationServiceImpl;
class GrpcServerTestPeer;

// 停止结果不依赖诊断字符串：路径残留不等于服务仍在运行。
enum class StopResult { Stopped, PathCleanupFailed, Incomplete };

// 管理同步 gRPC 服务与等待线程；调用方须持实例资格，使用专用 UDS 及可信父目录。
class GrpcServer {
public:
    explicit GrpcServer(LinkConfig config);
    // 不抛异常、不 detach；无法安全回收线程时终止进程，单纯路径残留不触发终止。
    ~GrpcServer() noexcept;

    // 成败独立于诊断；失败尽力回收，未完成时保留资源并禁止重启，可再次 Stop。
    // 启动等待、生命周期锁、Shutdown 和 join 仍可能长期阻塞（T2-03 延期）。
    LinkRc Start() noexcept;
    StopResult Stop() noexcept;
    // 返回最近一次启动/清理诊断的副本；清理错误追加而不覆盖启动原因。
    std::string LastError() const;
    // 运行期故障独立于启动结果；查询不等待生命周期锁，故障标记不依赖文本分配。
    bool HasRuntimeFailure() const noexcept;
    std::string RuntimeError() const;

private:
    friend class GrpcServerTestPeer;
    // 默认失败，只有监听和 UDS 身份检查全部通过后才显式成功。
    struct StartupResult {
        bool success = false;
        std::string diagnostic;
    };
    // 隔离外部调用边界；生产默认仍使用真实 gRPC、系统调用和线程。
    // 测试通过友元在启动前替换操作，不提供运行时修改依赖的公开接口。
    struct Operations {
        std::function<int(const char *, struct stat *)> stat = ::lstat;
        std::function<int(const char *)> unlink = ::unlink;
        std::function<std::unique_ptr<grpc::Server>(grpc::ServerBuilder &)> build = [](grpc::ServerBuilder &builder) {
            return builder.BuildAndStart();
        };
        std::function<void(grpc::Server &)> shutdown = [](grpc::Server &server) { server.Shutdown(); };
        std::function<void(grpc::Server &)> wait = [](grpc::Server &server) { server.Wait(); };
        std::function<void(std::thread &)> join = [](std::thread &thread) { thread.join(); };
        std::function<std::unique_ptr<std::thread>(GrpcServer &, std::promise<StartupResult>)> start =
            [](GrpcServer &owner, std::promise<StartupResult> ready) {
                return std::make_unique<std::thread>(&GrpcServer::RunServer, &owner, std::move(ready));
            };
        std::function<void(std::unique_ptr<grpc::Server> &)> destroy = [](std::unique_ptr<grpc::Server> &server) {
            server.reset();
        };
        std::function<void(std::promise<StartupResult> &, StartupResult)> publish =
            [](std::promise<StartupResult> &ready, StartupResult result) { ready.set_value(std::move(result)); };
        std::function<void(std::string &, const std::string &)> diagnostic =
            [](std::string &target, const std::string &text) { target = text; };
        std::function<void(const char *, bool)> log;
    };
    void RunServer(std::promise<StartupResult> ready) noexcept;
    bool PrepareSocket();
    bool RecordSocket(std::string &error);
    StopResult StopUnlocked() noexcept;
    StopResult CleanupSocket() noexcept;
    void SetDiagnostic(std::string &target, const char *text) noexcept;
    void AppendStopError(const char *stage, int error = 0) noexcept;
    void ReportRuntimeFailure(const char *text) noexcept;
    void Log(const char *text, bool warning = false) noexcept;
    std::string StartupContext(const char *stage, int tcp, int uds, const char *unavailable = nullptr) const;
    void AppendStartupContext(const char *stage, const char *unavailable) noexcept;

    LinkConfig config_;
    Operations operations_;
    // 串行化 Start/Stop 及启动/清理诊断读取，不承担迁移业务请求的并发准入。
    // 工作线程不获取此锁，避免调用方持锁等待启动结果或 join 时相互等待。
    mutable std::mutex lifecycleMutex_;
    std::string lastError_;
    // 单独保护运行期诊断文本；只在读写详情或重置故障状态的短作用域内持有。
    // 故障标志本身为原子变量；此锁与生命周期锁分离，供工作线程独立报告故障。
    mutable std::mutex faultMutex_;
    std::atomic<bool> runtimeFailed_{false};
    std::string runtimeError_;
    // 仅表示启动时观察到的身份，不证明可靠所有权；检查/删除非原子。
    dev_t socketDevice_ = 0;
    ino_t socketInode_ = 0;
    bool socketIdentityRecorded_ = false;

    // 业务对象必须覆盖 Server 完整生命周期；显式清理也严格先 server 后 service。
    std::unique_ptr<MigrationServiceImpl> service_;
    std::unique_ptr<grpc::Server> server_;
    std::unique_ptr<std::thread> server_thread_;
};
} // 命名空间 virtrust
