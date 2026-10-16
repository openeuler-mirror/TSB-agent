/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <sys/types.h>

#include <string>

#include "virtrust/base/process_file_lock.h"

namespace virtrust {
// 普通变更可共同进入；迁移独占本节点业务准入。
enum class AdmissionKind { OrdinaryMutation, Migration };

// 单个准入令牌；调用方须串行使用同一对象，移动后仅新对象持有资格。
// Try 仅不等待锁竞争，并不限制文件系统调用耗时或保证迁移公平性。
// 跨进程互斥要求参与者使用同一文件系统中的同一锁文件，不提供跨重启任务恢复。
class NodeAdmission {
public:
    NodeAdmission() = default;
    ~NodeAdmission() = default;
    NodeAdmission(const NodeAdmission &) = delete;
    NodeAdmission &operator=(const NodeAdmission &) = delete;
    NodeAdmission(NodeAdmission &&other) noexcept;
    NodeAdmission &operator=(NodeAdmission &&other) noexcept;

    // 默认生产目录归 root；测试可传入隔离目录和当前有效 UID。
    // 系统调用故障返回 Error，竞争返回 Busy；路径或诊断分配异常仍向调用方传播。
    LockOutcome TryAcquire(AdmissionKind kind, const std::string &directory = "/run/virtrust", uid_t owner = 0);
    // 仅关闭持有的描述符，不删除节点锁文件；保留最近一次获取的诊断。
    void Release() noexcept;
    bool OwnsAdmission() const noexcept;
    // 每次 TryAcquire 开始清空旧诊断；Release 不清空，便于调用方在清理后读取。
    int LastErrno() const noexcept;
    // 返回对象内部引用，后续获取或移动会改变内容，对象销毁后不得继续使用。
    const std::string &LastError() const noexcept;

private:
    ProcessFileLock lock_;
    int error_ = 0;
    std::string detail_;
};
} // 命名空间 virtrust
