/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/base/process_file_lock.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <utility>

namespace virtrust {
// 将退出作用域和主动释放统一到同一个清理入口。
ProcessFileLock::~ProcessFileLock()
{
    Release();
}
// 取走描述符的同时将来源置空，避免来源析构时关闭已转交的描述符。
ProcessFileLock::ProcessFileLock(ProcessFileLock &&other) noexcept
    : fd_(std::exchange(other.fd_, -1)), error_(std::exchange(other.error_, 0))
{}
// 自移动不做处理；不同对象之间转移前先释放接收方的旧资源。
ProcessFileLock &ProcessFileLock::operator=(ProcessFileLock &&other) noexcept
{
    if (this != &other) {
        Release();
        fd_ = std::exchange(other.fd_, -1);
        error_ = std::exchange(other.error_, 0);
    }
    return *this;
}

// 获取顺序：检查对象状态 → 打开文件 → 校验文件 → 申请内核锁 → 接管描述符。
LockOutcome ProcessFileLock::Acquire(const std::string &path, LockMode mode, LockWait wait)
{
    // 1、调用方式、文件路径、权限或系统操作存在问题，需要查看具体错误，不能当成普通竞争重试
    if (OwnsLock()) {
        // 当前对象已持锁，重复获取属于调用错误；保留原锁，不按 Busy 重试
        error_ = EALREADY;
        return LockOutcome::Error;
    }
    error_ = 0;
    // candidate 是尚未接管的临时描述符，后续任一步失败都须关闭。
    // O_CLOEXEC 在成功 exec 时关闭当前进程中的描述符副本，避免新程序继续持有锁，fork
    // 本身仍会继承描述符，不受此标志阻止。 O_NOFOLLOW 拒绝末级符号链接；O_NONBLOCK 是特殊文件打开的防御性标志，不决定
    // flock 的等待策略。 Linux 的 FIFO 以 O_RDWR 打开本身不等待对端；此标志也不保证所有设备打开均不阻塞。
    // 新文件请求权限 0600（仍受 umask 限制）；已有文件不会被自动修改权限。
    int candidate = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (candidate < 0) {
        error_ = errno;
        return LockOutcome::Error;
    }
    // 校验已打开的文件本体；父目录安全仍由调用方保证。
    struct stat info {};
    if (fstat(candidate, &info) != 0) {
        error_ = errno;
    } else if (!S_ISREG(info.st_mode) || info.st_nlink != 1) {
        // 仅接受单一硬链接的普通文件，拒绝 FIFO、设备及硬链接别名。
        error_ = EINVAL;
    } else if (info.st_uid != geteuid() || (info.st_mode & 0077) != 0) {
        // 文件须归当前有效用户所有，且组用户和其他用户均无访问权限。
        error_ = EACCES;
    }
    if (error_ != 0) {
        close(candidate);
        return LockOutcome::Error;
    }

    // 2、将共享/独占与等待策略分别映射到 flock 标志。
    const int operation = (mode == LockMode::Shared ? LOCK_SH : LOCK_EX) | (wait == LockWait::Try ? LOCK_NB : 0);
    // 信号中断不视为锁竞争；重试 flock，本接口不提供取消或超时控制。
    int result;
    do {
        result = flock(candidate, operation);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        error_ = errno;
        close(candidate);
        // 只有非阻塞加锁的竞争错误才是 Busy，其他故障统一返回 Error。
        return wait == LockWait::Try && (error_ == EWOULDBLOCK || error_ == EAGAIN) ? LockOutcome::Busy
                                                                                    : LockOutcome::Error;
    }
    fd_ = candidate;
    return LockOutcome::Acquired;
}

// 只关闭描述符，不主动解锁共享的内核打开文件描述，也不删除锁文件。
void ProcessFileLock::Release() noexcept
{
    if (fd_ >= 0) {
        // 不调用 LOCK_UN：fork 后父子进程共享内核打开文件描述，主动解锁会影响父进程。
        // 最后一个描述符副本关闭时，内核才释放锁；此处先将对象置空以防重复关闭。
        // Linux 上 close 返回 EINTR 也不重试，避免误关已被其他线程复用的描述符。
        close(std::exchange(fd_, -1));
    }
}
} // 命名空间 virtrust
