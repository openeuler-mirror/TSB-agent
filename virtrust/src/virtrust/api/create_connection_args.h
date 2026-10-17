/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace virtrust {
// 只解析创建命令的连接选项，不打开 libvirt 连接或判断目标是否可用。
struct CreateConnectionArgs {
    // 保留显式 URI 的出现顺序；无效值也占一个候选位置，交由调用方决定跳过或拒绝。
    std::vector<std::string> candidates;
    // 删除已识别的连接选项，其余 virt-install 参数保持原顺序。
    std::vector<std::string> argsWithoutConnection;
    // 即使显式选项缺值，也不能悄悄回退到项目默认 URI。
    bool hasExplicitOption = false;
};

// 解析器不负责选择连接：CLI 可以逐个尝试，直接 API 则必须核对已建立的连接。
CreateConnectionArgs ParseCreateConnectionArgs(const std::vector<std::string> &args);
// 仅做结构校验；libvirt 别名的存在使这里不能简单要求 URI 含有 "://"。
bool IsUsableConnectionCandidate(std::string_view uri);
} // namespace virtrust
