/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>

namespace virtrust {

// 每次人工发起迁移时生成新身份；随机源不可用即失败，不退化为可预测编号。
std::string GenerateMigrationAttemptId();

// 只接受生成器输出的固定形式；用于拒绝协议回复或 CLI 输入中的控制字符。
bool ValidMigrationAttemptId(const std::string &id) noexcept;

} // namespace virtrust
