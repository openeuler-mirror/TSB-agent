/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#pragma once

namespace virtrust {
// 入口函数通过静态字符串更新阶段，不为边界本身引入动态分配。
using EntryFunction = int (*)(int argc, char **argv, const char *&stage);
// 调用方提供非空函数；诊断尽力写入描述符，失败不改变退出码，不保证写入有界。
int RunEntryBoundary(int argc, char **argv, EntryFunction entry, int diagnosticFd = 2) noexcept;
} // 命名空间 virtrust
