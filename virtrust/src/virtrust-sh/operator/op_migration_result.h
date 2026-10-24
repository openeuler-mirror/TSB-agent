/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>

#include "virtrust-sh/operator/op_itf.h"

namespace virtrust {

// 人工只读查询目的节点已记录的最终通知结果，不发起或恢复迁移。
class OpMigrationResult final : public OpItf {
public:
    OpMigrationResult() : OpItf(OpTy::MIGRATION_RESULT) {}

    OpRc ParseArgv(int argc, char **argv) override;
    OpRc Exec() override;
    void PrintUsage() override;

private:
    std::string uuid_;
    std::string destUri_;
    std::string attemptId_;
};

} // namespace virtrust
