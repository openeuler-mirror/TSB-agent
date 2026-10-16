/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <sys/types.h>

#include <string>

namespace virtrust {
// 返回失败步骤、路径及 errno；成功时三项均清空。
struct RuntimeDirectoryError {
    int code = 0;
    std::string path;
    std::string step;
};

// 仅创建末级私有目录，逐级校验已有父目录，不修改任何已有权限。
// 路径含内嵌 NUL 时在文件系统操作前拒绝；路径或诊断分配异常仍由调用方处理。
bool EnsurePrivateRuntimeDirectory(const std::string &directory, uid_t owner, RuntimeDirectoryError &error);
} // 命名空间 virtrust
