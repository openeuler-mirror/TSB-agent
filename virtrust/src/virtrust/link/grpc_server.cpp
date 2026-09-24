/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include "virtrust/link/grpc_server.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "virtrust/base/logger.h"
#include "virtrust/base/str_utils.h"
#include "virtrust/link/migration_service_impl.h"

#include "virtrust/link/proto/migrate.grpc.pb.h"

namespace virtrust {
GrpcServer::GrpcServer(LinkConfig config) : config_(std::move(config))
{}
GrpcServer::~GrpcServer()
{
    Stop();
}

// 调用方必须已持有实例资格；本检查进一步保护非 Socket 文件和仍活动的端点。
bool GrpcServer::PrepareSocket()
{
    // 统一记录失败阶段和路径；仅系统调用失败时附加 errno，策略拒绝不伪造错误码。
    const auto fail = [this](const char *stage, int error = 0) {
        lastError_ = std::string(stage) + " [" + config_.udsPath + "]";
        if (error != 0) {
            lastError_ += ": errno=" + std::to_string(error) + " " + strerror(error);
        }
        return false;
    };
    sockaddr_un address{};
    if (config_.udsPath.empty() || config_.udsPath.front() != '/' ||
        config_.udsPath.size() >= sizeof(address.sun_path)) {
        return fail("Invalid UDS path: expected an absolute path within the length limit");
    }
    struct stat before {};
    if (lstat(config_.udsPath.c_str(), &before) != 0) {
        if (errno == ENOENT) {
            return true;
        }
        return fail("Initial UDS lstat failed", errno);
    }
    if (!S_ISSOCK(before.st_mode)) {
        return fail("UDS type check failed: not a socket; refusing removal");
    }
    if (before.st_uid != geteuid()) {
        return fail("UDS owner check failed: owned by another user; refusing removal");
    }
    // 临时探测连接
    int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (probe < 0) {
        return fail("Failed to create UDS probe socket", errno);
    }
    address.sun_family = AF_UNIX;
    config_.udsPath.copy(address.sun_path, sizeof(address.sun_path) - 1);
    const int result = connect(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    const int error = errno;
    close(probe);
    // ECONNREFUSED 仅表示本次连接被拒绝，不证明原进程死亡或端点属于本服务。
    // 视为候选遗留端点的前提是外层已持有实例锁，且部署保证此 UDS 路径专用于本服务。
    // 活动或无法判断的端点一律保留；不能作为任意同用户 Socket 的通用清理器。
    if (result == 0) {
        return fail("UDS probe connected: endpoint is active; refusing removal");
    }
    if (error != ECONNREFUSED) {
        return fail("UDS probe could not confirm inactivity; refusing removal", error);
    }
    struct stat current {};
    if (lstat(config_.udsPath.c_str(), &current) != 0) {
        return fail("Pre-removal UDS lstat failed", errno);
    }
    if (current.st_dev != before.st_dev || current.st_ino != before.st_ino) {
        return fail("UDS file identity changed before removal; refusing removal");
    }
    // 身份检查与 unlink 不是原子操作；同权限恶意替换不在当前保证范围内。
    if (unlink(config_.udsPath.c_str()) != 0) {
        return fail("Failed to unlink candidate stale UDS", errno);
    }
    return true;
}

LinkRc GrpcServer::Start()
{
    std::lock_guard<std::mutex> guard(lifecycleMutex_);
    if (server_thread_ && server_thread_->joinable()) {
        lastError_ = "Service already started or previous thread not yet joined";
        return LinkRc::ERROR;
    }
    lastError_.clear();
    if (!PrepareSocket()) {
        return LinkRc::ERROR;
    }
    try {
        std::promise<std::string> ready;
        auto result = ready.get_future();
        server_thread_ = std::make_unique<std::thread>(&GrpcServer::RunServer, this, std::move(ready));
        // 明确等到 BuildAndStart 成功或失败，不再固定睡眠后猜测结果。
        lastError_ = result.get();
    } catch (const std::exception &error) {
        lastError_ = error.what();
    }
    if (!lastError_.empty()) {
        StopUnlocked();
        return LinkRc::ERROR;
    }
    return LinkRc::OK;
}

void GrpcServer::Stop()
{
    std::lock_guard<std::mutex> guard(lifecycleMutex_);
    StopUnlocked();
}

std::string GrpcServer::LastError() const
{
    std::lock_guard<std::mutex> guard(lifecycleMutex_);
    return lastError_;
}

// 必须先通知 Shutdown，再等待工作线程结束，最后销毁服务对象。
void GrpcServer::StopUnlocked()
{
    if (server_) {
        server_->Shutdown();
    }
    if (server_thread_ && server_thread_->joinable()) {
        server_thread_->join();
    }
    server_thread_.reset();
    server_.reset();
    if (ownsSocket_) {
        struct stat current {};
        if (lstat(config_.udsPath.c_str(), &current) == 0 && S_ISSOCK(current.st_mode) &&
            current.st_dev == socketDevice_ && current.st_ino == socketInode_) {
            if (unlink(config_.udsPath.c_str()) != 0) {
                VIRTRUST_LOG_ERROR("|Stop|UDS cleanup failed|{}", strerror(errno));
            }
        }
        ownsSocket_ = false;
    }
}

void GrpcServer::RunServer(std::promise<std::string> ready)
{
    bool reported = false;
    try {
        // 服务实现必须活到 Wait 返回，不能在 Start 返回后成为悬空指针。
        MigrationServiceImpl service;
        // 插件只注册一次，允许同一进程中安全创建多个测试服务实例。
        static std::once_flag reflection;
        std::call_once(reflection, [] {
            grpc::EnableDefaultHealthCheckService(true);
            grpc::reflection::InitProtoReflectionServerBuilderPlugin();
        });
        grpc::ServerBuilder builder;
        auto credentials = grpc::InsecureServerCredentials();
        if (!config_.skPath.empty() && !config_.certPath.empty() && !config_.caPath.empty()) {
            grpc::SslServerCredentialsOptions::PemKeyCertPair pair;
            pair.private_key = ReadFile(config_.skPath);
            pair.cert_chain = ReadFile(config_.certPath);
            grpc::SslServerCredentialsOptions options;
            options.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
            options.pem_key_cert_pairs.push_back(pair);
            options.pem_root_certs = ReadFile(config_.caPath);
            credentials = grpc::SslServerCredentials(options);
        }
        int tcpPort = 0, udsPort = 0;
        builder.AddListeningPort(config_.ip + ":" + std::to_string(config_.port), credentials, &tcpPort);
        builder.AddListeningPort("unix:" + config_.udsPath, grpc::InsecureServerCredentials(), &udsPort);
        builder.RegisterService(&service);
        server_ = builder.BuildAndStart();
        struct stat info {};
        if (lstat(config_.udsPath.c_str(), &info) == 0 && S_ISSOCK(info.st_mode) && info.st_uid == geteuid()) {
            socketDevice_ = info.st_dev;
            socketInode_ = info.st_ino;
            ownsSocket_ = true;
        }
        if (!server_ || tcpPort == 0 || udsPort == 0) {
            // 部分监听成功也算整体失败；先停止服务，再允许局部 service 离开作用域。
            if (server_) {
                server_->Shutdown();
            }
            ready.set_value("gRPC startup failed: TCP or UDS listener unavailable; check addresses, permissions and "
                            "certificates; see gRPC logs for details");
            return;
        }
        ready.set_value("");
        reported = true;
        server_->Wait();
    } catch (const std::exception &error) {
        if (!reported) {
            ready.set_value(error.what());
        } else {
            VIRTRUST_LOG_ERROR("|RunServer|Server thread exception|{}", error.what());
        }
    } catch (...) {
        if (!reported) {
            ready.set_value("Unknown exception in gRPC server thread");
        } else {
            VIRTRUST_LOG_ERROR("|RunServer|Unknown exception in server thread");
        }
    }
}
} // namespace virtrust
