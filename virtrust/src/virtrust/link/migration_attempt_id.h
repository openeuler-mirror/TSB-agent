/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>

namespace virtrust {

// 每次人工发起迁移时生成新身份；随机源不可用即失败，不退化为可预测编号。
std::string GenerateMigrationAttemptId();

} // namespace virtrust
