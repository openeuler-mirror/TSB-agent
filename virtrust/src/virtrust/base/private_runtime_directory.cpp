/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/base/private_runtime_directory.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <iterator>

namespace virtrust {
namespace {
// 目录遍历中的临时描述符在路径操作抛异常时也必须关闭。
class DirectoryFd {
public:
    explicit DirectoryFd(int fd) : fd_(fd)
    {}
    ~DirectoryFd()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    DirectoryFd(const DirectoryFd &) = delete;
    DirectoryFd &operator=(const DirectoryFd &) = delete;
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

bool Fail(RuntimeDirectoryError &error, const std::string &path, const char *step, int code)
{
    error.code = code;
    error.path = path;
    error.step = step;
    return false;
}
} // 匿名命名空间

// 与守护进程实例锁共用同一套目录策略，避免两个调用入口产生不同信任边界。
bool EnsurePrivateRuntimeDirectory(const std::string &directory, uid_t owner, RuntimeDirectoryError &error)
{
    error = {};
    // 系统调用把 NUL 当作路径结束符，必须在创建目录前拒绝，避免校验与使用不同路径。
    if (directory.find('\0') != std::string::npos) {
        return Fail(error, directory, "Runtime directory path contains an embedded NUL byte", EINVAL);
    }
    const std::filesystem::path path(directory);
    if (!path.is_absolute() || path == "/" || path.filename().empty()) {
        return Fail(error, directory, "Instance directory must be an absolute non-root path", EINVAL);
    }
    if (geteuid() != owner) {
        return Fail(error, directory, "Effective UID does not match the required owner", EACCES);
    }

    // 每一级都按描述符相对打开，禁止祖先符号链接绕过末级检查。
    DirectoryFd parent(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (parent.Get() < 0) {
        return Fail(error, "/", "Failed to open root directory", errno);
    }
    const auto relative = path.relative_path();
    std::filesystem::path checked("/");
    for (auto it = relative.begin(); it != relative.end(); ++it) {
        const std::string part = it->string();
        const bool final = std::next(it) == relative.end();
        checked /= part;
        if (part == "." || part == "..") {
            return Fail(error, checked.string(), "Dot path components are not allowed", EINVAL);
        }
        // 只创建末级；已有目录的权限和属主绝不自动改写。
        if (final && mkdirat(parent.Get(), part.c_str(), 0700) != 0 && errno != EEXIST) {
            const int code = errno;
            return Fail(error, checked.string(), "Failed to create instance directory", code);
        }
        int current = openat(parent.Get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (current < 0) {
            const int code = errno;
            return Fail(error, checked.string(), "Failed to open directory (symbolic links are prohibited)", code);
        }
        parent.Reset(current);
        struct stat info {};
        if (fstat(parent.Get(), &info) != 0) {
            const int code = errno;
            return Fail(error, checked.string(), "Failed to read directory attributes", code);
        }
        if (final) {
            if (info.st_uid != owner) {
                return Fail(error, checked.string(), "Instance directory owner mismatch", EACCES);
            }
            if ((info.st_mode & 07777) != 0700) {
                return Fail(error, checked.string(),
                            "Instance directory permissions must be 0700; automatic changes are disabled", EACCES);
            }
        } else {
            // 保留 root 粘滞临时目录例外，部署中的 /run 不依赖它。
            const bool stickyRoot = info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0;
            if ((info.st_uid != 0 && info.st_uid != owner) || ((info.st_mode & 0022) != 0 && !stickyRoot)) {
                return Fail(error, checked.string(), "Untrusted parent directory owner or write permissions", EACCES);
            }
        }
    }
    return true;
}
} // 命名空间 virtrust
