/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "libvirtrustd/daemon_instance.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>

#include "virtrust/base/private_runtime_directory.h"

namespace virtrust {

// 锁竞争只返回 Busy；目录错误或服务启动错误保留可读诊断。
LockOutcome DaemonRuntime::Start() noexcept
{
    // 仅允许本次成功取得资格的调用清理服务，重复 Start 不能停止已有实例。
    bool acquiredHere = false;
    try {
        const auto acquired = instance_.Acquire(directory_, owner_);
        if (acquired != LockOutcome::Acquired) {
            try {
                error_ = instance_.LastError();
                stopErrorOffset_.reset();
            } catch (...) {
            }
            return acquired;
        }
        acquiredHere = true;
        if (server_.Start() == LinkRc::OK) {
            error_.clear();
            stopErrorOffset_.reset();
            return LockOutcome::Acquired;
        }
        error_ = server_.LastError();
        stopErrorOffset_.reset();
    } catch (const std::exception &error) {
        try {
            error_ = std::string("Daemon startup exception [") + directory_ + "]: " + error.what();
            stopErrorOffset_.reset();
        } catch (...) {
        }
    } catch (...) {
        try {
            error_ = std::string("Unknown daemon startup exception [") + directory_ + "]";
            stopErrorOffset_.reset();
        } catch (...) {
        }
    }
    if (acquiredHere) {
        // 即使失败来自异常，也必须先回收服务再释放资格；资源回收未完成时保留资格。
        Stop();
    }
    return LockOutcome::Error;
}

StopResult DaemonRuntime::Stop() noexcept
{
    const auto result = server_.Stop();
    // 资格释放只取决于资源回收状态，不能依赖诊断字符串是否成功生成。
    if (result != StopResult::Incomplete) {
        instance_ = DaemonInstance{};
    }
    if (result != StopResult::Stopped) {
        try {
            // 在临时文本中重建后再发布；分配失败时原诊断与后缀位置均保持不变。
            const auto offset = stopErrorOffset_.value_or(error_.size());
            auto text = error_.substr(0, offset);
            const auto snapshot = server_.LastError();
            if (!text.empty() && !snapshot.empty()) {
                text += "; ";
            }
            text += snapshot;
            error_ = std::move(text);
            stopErrorOffset_ = offset;
        } catch (...) {
        }
    }
    return result;
}

int DaemonRuntime::RunUntilStopped(const std::function<bool()> &stopRequested) noexcept
{
    bool failed = false;
    try {
        while (!server_.HasRuntimeFailure() && !stopRequested()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (...) {
        failed = true;
        try {
            error_ = "Daemon main loop failed";
            stopErrorOffset_.reset();
        } catch (...) {
        }
    }
    const auto stopped = Stop();
    // join 后运行期诊断已稳定，避免故障标记先于文本发布或故障在停止期间发生而丢失原因。
    // 未完成停止时仍只能读取当前快照；诊断失败不能影响资源/资格保留策略。
    if (server_.HasRuntimeFailure()) {
        failed = true;
        try {
            auto runtimeError = server_.RuntimeError();
            if (runtimeError.empty()) {
                runtimeError = "Server runtime failure; diagnostic unavailable";
            }
            const auto prefixLength = runtimeError.size();
            const bool hasPrevious = !error_.empty();
            if (hasPrevious) {
                runtimeError += "; " + error_;
            }
            error_ = std::move(runtimeError);
            // 运行原因前置后，停止后缀位置同步平移，后续失败重试仍只替换停止部分。
            if (stopErrorOffset_) {
                // 原业务前缀为空时，新分隔符属于可替换后缀，不能计入保留前缀。
                *stopErrorOffset_ += prefixLength + (*stopErrorOffset_ != 0 ? 2 : 0);
            }
        } catch (...) {
        }
    }
    return failed || stopped != StopResult::Stopped ? 1 : 0;
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

    RuntimeDirectoryError directoryError;
    if (!EnsurePrivateRuntimeDirectory(directory, owner, directoryError)) {
        return Fail(directoryError.path, directoryError.step.c_str(), directoryError.code);
    }
    // 已验证路径各级不可由非可信用户替换；同权限恶意进程不属于锁的安全边界。
    const std::string lockPath = directory + "/libvirtrustd.lock";
    const auto result = lock_.Acquire(lockPath, LockMode::Exclusive, LockWait::Try);
    error_ = lock_.LastErrno();
    if (result != LockOutcome::Acquired) {
        Fail(lockPath,
             result == LockOutcome::Busy ? "Another instance holds the lock on this node"
                                         : "Failed to acquire instance lock",
             error_);
    }
    return result;
}
} // 命名空间 virtrust
