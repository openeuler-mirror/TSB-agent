/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */
#include "virtrust/link/grpc_server.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <stdexcept>

#include "virtrust/base/logger.h"
#include "virtrust/base/str_utils.h"
#include "virtrust/link/migration_service_impl.h"

namespace virtrust {
namespace {
// 校验期间独占目录描述符；错误文本分配抛异常时也必须关闭。
class UdsDirectoryFd {
public:
    explicit UdsDirectoryFd(int fd) : fd_(fd)
    {}
    ~UdsDirectoryFd()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    UdsDirectoryFd(const UdsDirectoryFd &) = delete;
    UdsDirectoryFd &operator=(const UdsDirectoryFd &) = delete;
    int Get() const noexcept
    {
        return fd_;
    }
    void Reset(int fd) noexcept
    {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

// 只校验，不创建或修复目录。生产目录由 root 实例资格流程建立，配置层固定端点。
// 底层服务允许测试使用当前用户的独立 0700 目录；不改变生产 root-only 策略。
std::string CheckUdsParent(const std::string &socketPath)
{
    const auto fail = [&](const char *reason, int error = 0) {
        auto text = std::string("UDS parent check failed [") + socketPath + "]: " + reason;
        if (error != 0) {
            text += "; errno=" + std::to_string(error) + " " + strerror(error);
        }
        return text;
    };
    const std::filesystem::path path(socketPath);
    if (socketPath.find('\0') != std::string::npos || !path.is_absolute() || path.filename().empty() ||
        path.filename() == "." || path.filename() == ".." || path.parent_path() == "/") {
        return fail("expected an absolute endpoint in a dedicated directory");
    }
    UdsDirectoryFd directory(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory.Get() < 0) {
        return fail("cannot open root directory", errno);
    }
    const auto relative = path.parent_path().relative_path();
    for (auto it = relative.begin(); it != relative.end(); ++it) {
        const auto part = it->string();
        if (part.empty() || part == "." || part == "..") {
            return fail("dot or empty directory components are prohibited");
        }
        const int fd = openat(directory.Get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            return fail("cannot open directory; symbolic links are prohibited", errno);
        }
        directory.Reset(fd);
        struct stat info {};
        if (fstat(directory.Get(), &info) != 0) {
            return fail("cannot read directory attributes", errno);
        }
        if (std::next(it) == relative.end()) {
            if (info.st_uid != geteuid() || (info.st_mode & 07777) != 0700) {
                return fail("dedicated directory must be owned by the effective UID with mode 0700");
            }
        } else {
            // 与实例目录策略一致：为隔离测试保留 root 粘滞祖先目录例外，生产 /run 不依赖它。
            // 此分支也存在于生产构建中，并非测试专用开关或 /tmp 路径白名单。
            const bool stickyRoot = info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0;
            if ((info.st_uid != 0 && info.st_uid != geteuid()) || ((info.st_mode & 0022) != 0 && !stickyRoot)) {
                return fail("untrusted ancestor owner or write permissions");
            }
        }
    }
    // 不抵御同权限进程在检查后替换目录，也不约束 gRPC 内部的路径清理。
    return {};
}
} // 匿名命名空间

GrpcServer::GrpcServer(LinkConfig config) : config_(std::move(config))
{
    operations_.log = [](const char *text, bool warning) {
        if (warning) {
            VIRTRUST_LOG_WARN("|GrpcServer|{}", text);
        } else {
            VIRTRUST_LOG_INFO("|GrpcServer|{}", text);
        }
    };
}
GrpcServer::~GrpcServer() noexcept
{
    if (Stop() == StopResult::Incomplete) {
        // 未确认线程停止时禁止继续析构或 detach，避免悬空引用及提前释放实例资格。
        std::terminate();
    }
}
void GrpcServer::SetDiagnostic(std::string &target, const char *text) noexcept
{
    try {
        operations_.diagnostic(target, text && *text ? text : "Operation failed without diagnostic details");
    } catch (...) {
        // 文本分配失败不能改变独立的失败状态，也不能阻断资源回收。
    }
}
void GrpcServer::Log(const char *text, bool warning) noexcept
{
    try {
        operations_.log(text, warning);
    } catch (...) {
        // 尽力诊断，二次异常不能逃出线程或析构。
    }
}
bool GrpcServer::HasRuntimeFailure() const noexcept
{
    return runtimeFailed_.load(std::memory_order_acquire);
}
std::string GrpcServer::RuntimeError() const
{
    std::lock_guard<std::mutex> guard(faultMutex_);
    return runtimeError_;
}
void GrpcServer::ReportRuntimeFailure(const char *text) noexcept
{
    runtimeFailed_.store(true, std::memory_order_release);
    try {
        std::lock_guard<std::mutex> guard(faultMutex_);
        SetDiagnostic(runtimeError_, text);
    } catch (...) {
    }
    Log(text && *text ? text : "Server thread failed without diagnostic details", true);
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
    const auto parentError = CheckUdsParent(config_.udsPath);
    if (!parentError.empty()) {
        lastError_ = parentError;
        return false;
    }
    struct stat before {};
    if (operations_.stat(config_.udsPath.c_str(), &before) != 0) {
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
    if (operations_.stat(config_.udsPath.c_str(), &current) != 0) {
        return fail("Pre-removal UDS lstat failed", errno);
    }
    if (current.st_dev != before.st_dev || current.st_ino != before.st_ino) {
        return fail("UDS file identity changed before removal; refusing removal");
    }
    // 身份检查与 unlink 不是原子操作；同权限恶意替换不在当前保证范围内。
    if (operations_.unlink(config_.udsPath.c_str()) != 0) {
        return fail("Failed to unlink candidate stale UDS", errno);
    }
    return true;
}

LinkRc GrpcServer::Start() noexcept
{
    // 先关联互斥量但不加锁，再在 try 内显式加锁，使加锁异常转换为 ERROR。
    // guard 跨越后续启动流程；持锁时返回或离开作用域均自动解锁。
    std::unique_lock<std::mutex> guard(lifecycleMutex_, std::defer_lock);
    try {
        guard.lock();
    } catch (...) {
        // 未取得生命周期锁，不能安全更新受其保护的 lastError_。
        return LinkRc::ERROR;
    }
    // 线程退出但资源未回收时仍禁止重启；重复启动不清理原服务。
    if (server_thread_ || server_ || service_) {
        SetDiagnostic(lastError_, "Service already started or previous resources not yet reclaimed");
        AppendStartupContext("Repeated Start rejected", "not_attempted");
        return LinkRc::ERROR;
    }
    lastError_.clear();
    bool success = false;
    bool received = false;
    const char *stage = "Startup precheck";
    const char *unavailable = "not_attempted";
    try {
        {
            // 此处只需短作用域持锁：构造时加锁，离开花括号时自动解锁。
            // 加锁异常由外层 try 捕获；不持故障锁执行 UDS 操作或等待启动通知。
            std::lock_guard<std::mutex> faultGuard(faultMutex_);
            runtimeError_.clear();
            runtimeFailed_.store(false, std::memory_order_release);
        }
        if (socketIdentityRecorded_ && CleanupSocket() != StopResult::Stopped) {
            AppendStartupContext("Previous UDS cleanup", unavailable);
            return LinkRc::ERROR;
        }
        if (!PrepareSocket()) {
            AppendStartupContext(stage, unavailable);
            return LinkRc::ERROR;
        }
        stage = "Thread creation";
        std::promise<StartupResult> ready;
        auto result = ready.get_future();
        server_thread_ = operations_.start(*this, std::move(ready));
        stage = "Startup notification";
        unavailable = "unknown";
        // future 同步资源成员发布；T2-03 延期，不添加孤立的超时返回。
        auto startup = result.get();
        received = true;
        success = startup.success;
        if (!success) {
            SetDiagnostic(lastError_, startup.diagnostic.c_str());
        }
    } catch (const std::exception &error) {
        SetDiagnostic(lastError_, error.what());
    } catch (...) {
        SetDiagnostic(lastError_, "Unknown exception during server startup");
    }
    if (!success) {
        if (!received) {
            AppendStartupContext(stage, unavailable);
        }
        StopUnlocked();
        return LinkRc::ERROR;
    }
    return LinkRc::OK;
}
StopResult GrpcServer::Stop() noexcept
{
    try {
        std::lock_guard<std::mutex> guard(lifecycleMutex_);
        return StopUnlocked();
    } catch (...) {
        return StopResult::Incomplete;
    }
}
std::string GrpcServer::LastError() const
{
    std::lock_guard<std::mutex> guard(lifecycleMutex_);
    return lastError_;
}
void GrpcServer::AppendStopError(const char *stage, int error, const char *detail) noexcept
{
    try {
        std::string text = lastError_;
        if (!text.empty()) {
            text += "; ";
        }
        text += std::string(stage) + " [uds=" + config_.udsPath + "]";
        if (error != 0) {
            text += ": errno=" + std::to_string(error) + " " + strerror(error);
        }
        if (detail != nullptr && *detail != '\0') {
            text += ": ";
            text += detail;
        }
        operations_.diagnostic(lastError_, text);
    } catch (...) {
    }
}
// 清理失败保留原身份，后续重试仍拒绝删除替换后的对象。
StopResult GrpcServer::CleanupSocket() noexcept
{
    if (!socketIdentityRecorded_) {
        return StopResult::Stopped;
    }
    try {
        // 清理时重新检查，不能沿用启动时的权限快照；拒绝后保留身份供修复目录后重试。
        const auto parentError = CheckUdsParent(config_.udsPath);
        if (!parentError.empty()) {
            AppendStopError("UDS cleanup refused", 0, parentError.c_str());
            return StopResult::PathCleanupFailed;
        }
        struct stat current {};
        if (operations_.stat(config_.udsPath.c_str(), &current) != 0) {
            const int error = errno;
            if (error == ENOENT) {
                socketIdentityRecorded_ = false;
                return StopResult::Stopped;
            }
            AppendStopError("UDS cleanup lstat failed", error);
            return StopResult::PathCleanupFailed;
        }
        if (!S_ISSOCK(current.st_mode) || current.st_dev != socketDevice_ || current.st_ino != socketInode_) {
            AppendStopError("UDS cleanup identity mismatch; refusing removal");
            return StopResult::PathCleanupFailed;
        }
        if (operations_.unlink(config_.udsPath.c_str()) != 0) {
            const int error = errno;
            if (error != ENOENT) {
                AppendStopError("UDS cleanup unlink failed", error);
                return StopResult::PathCleanupFailed;
            }
        }
        socketIdentityRecorded_ = false;
        return StopResult::Stopped;
    } catch (...) {
        AppendStopError("Exception during UDS cleanup");
        return StopResult::PathCleanupFailed;
    }
}
// 必须完成 Shutdown、join、server 销毁后才能销毁 service；失败保留后续资源。
StopResult GrpcServer::StopUnlocked() noexcept
{
    const char *stage = "Server Shutdown failed";
    try {
        if (server_) {
            operations_.shutdown(*server_);
        }
        stage = "Server thread join failed";
        if (server_thread_ && server_thread_->joinable()) {
            operations_.join(*server_thread_);
        }
        if (server_thread_ && server_thread_->joinable()) {
            AppendStopError("Server thread remains joinable");
            return StopResult::Incomplete;
        }
        server_thread_.reset();
        stage = "Server destruction failed";
        if (server_) {
            operations_.destroy(server_);
        }
        if (server_) {
            AppendStopError("Server object remains alive");
            return StopResult::Incomplete;
        }
        service_.reset();
    } catch (const std::exception &error) {
        // 异常对象在当前catch内有效；诊断尽力复制，失败仍保留未回收资源。
        AppendStopError(stage, 0, error.what());
        return StopResult::Incomplete;
    } catch (...) {
        AppendStopError(stage, 0, "Unknown exception");
        return StopResult::Incomplete;
    }
    const auto result = CleanupSocket();
    if (result == StopResult::PathCleanupFailed) {
        Log("Server stopped, but UDS path cleanup is incomplete", true);
    }
    return result;
}
std::string GrpcServer::StartupContext(const char *stage, int tcp, int uds, const char *unavailable) const
{
    return std::string(stage) + " [tcp=" + config_.ip + ":" + std::to_string(config_.port) +
           ", uds=" + config_.udsPath +
           ", server_created=" + (unavailable ? unavailable : (server_ ? "true" : "false")) +
           ", tcp_result=" + (unavailable ? std::string(unavailable) : std::to_string(tcp)) +
           ", uds_result=" + (unavailable ? std::string(unavailable) : std::to_string(uds)) +
           "]; see gRPC logs for underlying details";
}
void GrpcServer::AppendStartupContext(const char *stage, const char *unavailable) noexcept
{
    try {
        const auto text = StartupContext(stage, 0, 0, unavailable) + ": " + lastError_;
        operations_.diagnostic(lastError_, text);
    } catch (...) {
        // 未执行的监听不伪装成绑定失败；文本失败不改变启动状态。
    }
}
bool GrpcServer::RecordSocket(std::string &error)
{
    struct stat info {};
    if (operations_.stat(config_.udsPath.c_str(), &info) != 0) {
        const int saved = errno;
        error = "Post-start UDS lstat failed [uds=" + config_.udsPath + "]: errno=" + std::to_string(saved) + " " +
                strerror(saved);
        return false;
    }
    if (!S_ISSOCK(info.st_mode)) {
        error = "Post-start UDS type check failed [uds=" + config_.udsPath + "]";
        return false;
    }
    if (info.st_uid != geteuid()) {
        error = "Post-start UDS owner check failed [uds=" + config_.udsPath + "]";
        return false;
    }
    // 观察到的快照不证明可靠所有权，也不约束 gRPC 自身清理。
    socketDevice_ = info.st_dev;
    socketInode_ = info.st_ino;
    socketIdentityRecorded_ = true;
    return true;
}
void GrpcServer::RunServer(std::promise<StartupResult> ready) noexcept
{
    StartupResult result;
    const char *stage = "Service initialization";
    int tcpResult = 0;
    int udsResult = 0;
    bool buildAttempted = false;
    try {
        service_ = std::make_unique<MigrationServiceImpl>();
        // 仅保证本初始化操作一次执行，不代表任意服务实例整体线程安全。
        static std::once_flag reflection;
        std::call_once(reflection, [] {
            grpc::EnableDefaultHealthCheckService(true);
            grpc::reflection::InitProtoReflectionServerBuilderPlugin();
        });
        stage = "TLS configuration";
        const unsigned configured = static_cast<unsigned>(!config_.skPath.empty()) +
                                    static_cast<unsigned>(!config_.certPath.empty()) +
                                    static_cast<unsigned>(!config_.caPath.empty());
        if (configured != 0 && configured != 3) {
            result.diagnostic = "Incomplete TLS configuration: missing=";
            if (config_.skPath.empty()) {
                result.diagnostic += "private_key ";
            }
            if (config_.certPath.empty()) {
                result.diagnostic += "certificate ";
            }
            if (config_.caPath.empty()) {
                result.diagnostic += "ca ";
            }
        } else {
            auto credentials = grpc::InsecureServerCredentials();
            if (configured == 3) {
                // 按读取顺序立即检查，定位首个失败凭据；仅报告类别/路径，不输出内容或猜测 errno。
                const auto readCredential = [](const char *kind, const std::string &path) {
                    auto content = ReadFile(path);
                    if (content.empty()) {
                        throw std::runtime_error(std::string("TLS ") + kind + " read failed or file is empty [" + path +
                                                 "]; no plaintext fallback");
                    }
                    return content;
                };
                grpc::SslServerCredentialsOptions::PemKeyCertPair pair;
                pair.private_key = readCredential("private_key", config_.skPath);
                pair.cert_chain = readCredential("certificate", config_.certPath);
                grpc::SslServerCredentialsOptions options;
                options.pem_root_certs = readCredential("ca", config_.caPath);
                options.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
                options.pem_key_cert_pairs.push_back(std::move(pair));
                credentials = grpc::SslServerCredentials(options);
                Log("TCP mode: mutual TLS; UDS mode: local non-TLS");
            } else {
                Log("TCP mode: non-TLS (no credentials configured); UDS mode: local non-TLS", true);
            }
            stage = "BuildAndStart";
            grpc::ServerBuilder builder;
            builder.AddListeningPort(config_.ip + ":" + std::to_string(config_.port), credentials, &tcpResult);
            builder.AddListeningPort("unix:" + config_.udsPath, grpc::InsecureServerCredentials(), &udsResult);
            builder.RegisterService(service_.get());
            buildAttempted = true;
            server_ = operations_.build(builder);
            if (!server_ || tcpResult == 0 || udsResult == 0) {
                result.diagnostic = "Required listeners did not all start";
            } else {
                stage = "UDS identity validation";
                if (RecordSocket(result.diagnostic)) {
                    result.success = true;
                }
            }
        }
    } catch (const std::exception &error) {
        result.success = false;
        SetDiagnostic(result.diagnostic, error.what());
    } catch (...) {
        result.success = false;
        SetDiagnostic(result.diagnostic, "Unknown exception during server startup");
    }
    if (!result.success) {
        try {
            const auto detail =
                StartupContext(stage, tcpResult, udsResult, buildAttempted ? nullptr : "not_attempted") + ": " +
                result.diagnostic;
            operations_.diagnostic(result.diagnostic, detail);
        } catch (...) {
            // 诊断增强失败仍保留原有失败状态和已生成的首个原因。
        }
    }
    const bool started = result.success;
    try {
        // 只尝试一次通知，失败不重发；仅在结果尚未发布时，promise 析构才以 broken_promise 唤醒等待方。
        operations_.publish(ready, std::move(result));
    } catch (...) {
        ReportRuntimeFailure("Startup notification failed");
        return;
    }
    if (!started) {
        return;
    }
    try {
        operations_.wait(*server_);
    } catch (const std::exception &error) {
        ReportRuntimeFailure(error.what());
    } catch (...) {
        ReportRuntimeFailure("Unknown exception in server thread");
    }
}
} // 命名空间 virtrust
