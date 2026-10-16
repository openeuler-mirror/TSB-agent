/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/base/node_admission.h"

#include <cerrno>
#include <cstring>
#include <utility>

#include "virtrust/base/private_runtime_directory.h"

namespace virtrust {
namespace {
std::string Describe(const std::string &step, const std::string &path, int code)
{
    return step + " [" + path + "]: errno=" + std::to_string(code) + " " + strerror(code);
}
} // 匿名命名空间

// 令牌移动只转交底层打开文件描述，来源对象析构不会释放新对象的锁。
NodeAdmission::NodeAdmission(NodeAdmission &&other) noexcept
    : lock_(std::move(other.lock_)), error_(std::exchange(other.error_, 0)), detail_(std::move(other.detail_))
{}

NodeAdmission &NodeAdmission::operator=(NodeAdmission &&other) noexcept
{
    if (this != &other) {
        lock_ = std::move(other.lock_);
        error_ = std::exchange(other.error_, 0);
        detail_ = std::move(other.detail_);
    }
    return *this;
}

LockOutcome NodeAdmission::TryAcquire(AdmissionKind kind, const std::string &directory, uid_t owner)
{
    error_ = 0;
    detail_.clear();
    if (lock_.OwnsLock()) {
        error_ = EALREADY;
        detail_ = Describe("Admission object already holds a lock", directory, error_);
        return LockOutcome::Error;
    }
    if (kind != AdmissionKind::OrdinaryMutation && kind != AdmissionKind::Migration) {
        error_ = EINVAL;
        detail_ = Describe("Invalid node admission kind", directory, error_);
        return LockOutcome::Error;
    }
    RuntimeDirectoryError directoryError;
    if (!EnsurePrivateRuntimeDirectory(directory, owner, directoryError)) {
        error_ = directoryError.code;
        detail_ = Describe(directoryError.step, directoryError.path, error_);
        return LockOutcome::Error;
    }

    const auto lockPath = directory + "/node-admission.lock";
    const auto mode = kind == AdmissionKind::OrdinaryMutation ? LockMode::Shared : LockMode::Exclusive;
    const auto outcome = lock_.Acquire(lockPath, mode, LockWait::Try);
    error_ = lock_.LastErrno();
    if (outcome != LockOutcome::Acquired) {
        detail_ = Describe(outcome == LockOutcome::Busy ? "Node admission is held by another operation"
                                                       : "Failed to acquire node admission",
                           lockPath, error_);
    }
    return outcome;
}

void NodeAdmission::Release() noexcept
{
    lock_.Release();
}

bool NodeAdmission::OwnsAdmission() const noexcept
{
    return lock_.OwnsLock();
}

int NodeAdmission::LastErrno() const noexcept
{
    return error_;
}

const std::string &NodeAdmission::LastError() const noexcept
{
    return detail_;
}
} // 命名空间 virtrust
