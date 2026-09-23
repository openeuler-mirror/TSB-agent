/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "libvirtrustd/daemon_instance.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>
namespace virtrust {
namespace {
// 目录遍历中的临时描述符必须在字符串/路径操作抛异常时也关闭。
class DirectoryFd {
public:
    explicit DirectoryFd(int fd) : fd_(fd) {}
    ~DirectoryFd() { if (fd_ >= 0) { close(fd_); } }
    DirectoryFd(const DirectoryFd &) = delete;
    DirectoryFd &operator=(const DirectoryFd &) = delete;
    int Get() const noexcept { return fd_; }
    void Reset(int fd) noexcept { if (fd_ >= 0) { close(fd_); } fd_ = fd; }
private:
    int fd_;
};
} // 匿名命名空间

// 锁竞争只返回 Busy；目录错误或服务启动错误保留可读诊断。
LockOutcome DaemonRuntime::Start()
{
    // 仅允许本次成功取得资格的调用清理服务，重复 Start 不能停止已有实例。
    bool acquiredHere = false;
    try {
        const auto acquired = instance_.Acquire(directory_, owner_);
        if (acquired != LockOutcome::Acquired) {
            error_ = instance_.LastError();
            return acquired;
        }
        acquiredHere = true;
        if (server_.Start() == LinkRc::OK) {
            error_.clear();
            return LockOutcome::Acquired;
        }
        error_ = server_.LastError();
    } catch (const std::exception &error) {
        error_ = std::string("Daemon startup exception [") + directory_ + "]: " + error.what();
    } catch (...) {
        error_ = std::string("Unknown daemon startup exception [") + directory_ + "]";
    }
    if (acquiredHere) {
        // 即使失败来自异常，也必须先回收服务再释放资格；清理失败则保留资格。
        try { server_.Stop(); }
        catch (...) {
            error_ += "; service cleanup threw an exception; retaining instance lock to prevent duplicate startup";
            return LockOutcome::Error;
        }
        instance_ = DaemonInstance {};
    }
    return LockOutcome::Error;
}

LockOutcome DaemonInstance::Fail(const std::string &path, const char *step, int error)
{
    error_ = error;
    detail_ = std::string(step) + " [" + path + "]: errno=" + std::to_string(error) + " " + strerror(error);
    return LockOutcome::Error;
}

// 本类仅保证同一文件系统/锁命名空间中的实例互斥，不实现任务跨重启恢复。
LockOutcome DaemonInstance::Acquire(const std::string &directory, uid_t owner)
{
    error_ = 0;
    detail_.clear();
    if (lock_.OwnsLock()) {
        return Fail(directory, "Instance object already holds a lock; refusing repeated acquisition", EALREADY);
    }

    const std::filesystem::path path(directory);
    if (!path.is_absolute() || path == "/" || path.filename().empty()) {
        return Fail(directory, "Instance directory must be an absolute non-root path", EINVAL);
    }
    if (geteuid() != owner) {
        return Fail(directory, "Effective UID does not match the required owner", EACCES);
    }

    // 逐级以 NOFOLLOW 打开目录，不能仅检查末级而漏过父目录符号链接。
    DirectoryFd parent(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (parent.Get() < 0) {
        return Fail("/", "Failed to open root directory", errno);
    }
    const auto relative = path.relative_path();
    std::filesystem::path checked("/");
    for (auto it = relative.begin(); it != relative.end(); ++it) {
        const std::string part = it->string();
        const bool final = std::next(it) == relative.end();
        checked /= part;
        if (part == "." || part == "..") {
            return Fail(checked.string(), "Dot path components are not allowed", EINVAL);
        }
        // 只创建末级目录，不递归创建未知父目录，不修改已有目录权限。
        if (final && mkdirat(parent.Get(), part.c_str(), 0700) != 0 && errno != EEXIST) {
            const int error = errno;
            return Fail(checked.string(), "Failed to create instance directory", error);
        }

        int current = openat(parent.Get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (current < 0) {
            const int error = errno;
            return Fail(checked.string(), "Failed to open directory (symbolic links are prohibited)", error);
        }
        parent.Reset(current);
        struct stat info {};
        if (fstat(parent.Get(), &info) != 0) {
            const int error = errno;
            return Fail(checked.string(), "Failed to read directory attributes", error);
        }
        if (final) {
            if (info.st_uid != owner) {
                return Fail(checked.string(), "Instance directory owner mismatch", EACCES);
            }
            if ((info.st_mode & 07777) != 0700) {
                return Fail(checked.string(), "Instance directory permissions must be 0700; automatic changes are disabled", EACCES);
            }
        } else {
            // 允许 root 的粘滞临时目录用于隔离测试，S_ISVTX表示sticky bit，对删除/重命名其他用户的目录项增加了限制；
            // 部署 /run 不依赖此例外。
            const bool stickyRoot = info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0;
            if ((info.st_uid != 0 && info.st_uid != owner) || ((info.st_mode & 0022) != 0 && !stickyRoot)) {
                return Fail(checked.string(), "Untrusted parent directory owner or write permissions", EACCES);
            }
        }
    }
    // 已验证路径各级不可由非可信用户替换；同权限恶意进程不属于锁的安全边界。
    const std::string lockPath = directory + "/libvirtrustd.lock";
    const auto result = lock_.Acquire(lockPath, LockMode::Exclusive, LockWait::Try);
    error_ = lock_.LastErrno();
    if (result != LockOutcome::Acquired) {
        Fail(lockPath, result == LockOutcome::Busy ? "Another instance holds the lock on this node" : "Failed to acquire instance lock", error_);
    }
    return result;
}
} // 命名空间 virtrust
