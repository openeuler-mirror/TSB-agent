/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>

namespace virtrust {
// 共享锁可共同持有；独占锁与其他共享锁、独占锁均互斥。
enum class LockMode { Shared, Exclusive };
// Block 等待锁可用（无内置超时）；Try 在竞争失败时立即返回。
enum class LockWait { Block, Try };
// 区分成功、锁竞争和系统错误，避免将权限或路径故障误报为业务忙。
enum class LockOutcome { Acquired, Busy, Error };

// 跨进程文件锁：对象管理一个文件描述符，通过析构自动释放持有责任。
// 同一对象不支持多线程并发修改；不同对象之间通过内核锁协调。
// 调用方须保证父目录可信，且有潜在竞争者时不得删除或替换锁文件。
// 本类不创建或校验父目录；即使启用 VIRTRUST_MOCK，也使用真实内核锁。
class ProcessFileLock {
public:
    // 构造空对象，不打开文件、不申请锁。
    ProcessFileLock() = default;
    // 自动关闭本对象持有的描述符，不删除锁文件。
    ~ProcessFileLock();
    // 禁止复制，避免多个对象重复关闭同一个描述符。
    ProcessFileLock(const ProcessFileLock &) = delete;
    ProcessFileLock &operator=(const ProcessFileLock &) = delete;
    // 移动构造接管所有权，原对象置空；不释放再重新获取锁。
    ProcessFileLock(ProcessFileLock &&other) noexcept;
    // 移动赋值先释放自身旧描述符，再接管来源对象的所有权。
    ProcessFileLock &operator=(ProcessFileLock &&other) noexcept;
    // 打开并校验锁文件后申请锁；已持锁时返回 Error/EALREADY，保留原锁。
    // Busy 或 Error 的具体原因通过 LastErrno 获取；成功后错误码清零。
    LockOutcome Acquire(const std::string &path, LockMode mode, LockWait wait);
    // 可重复调用；仅关闭本对象的描述符，不清空最近获取操作的错误码。
    // fork 后若还有继承副本，内核锁须等最后一个副本关闭才释放。
    void Release() noexcept;
    // 查询本对象是否持有描述符，不重新查询系统锁状态。
    bool OwnsLock() const noexcept
    {
        return fd_ >= 0;
    }
    // 最近一次 Acquire 的错误码；应结合该次返回值判断，不代表释放结果。
    int LastErrno() const noexcept
    {
        return error_;
    }

private:
    // 仅在校验和加锁均成功后接管描述符；-1 表示空对象或已释放。
    int fd_ = -1;
    // 保存系统 errno 或接口校验错误，避免清理描述符时丢失故障原因。
    int error_ = 0;
};
} // namespace virtrust
