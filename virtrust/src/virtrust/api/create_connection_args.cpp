/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/api/create_connection_args.h"

#include <algorithm>

#include "virtrust/api/define_private.h"

namespace virtrust {
bool IsUsableConnectionCandidate(std::string_view uri)
{
    if (uri.empty() || uri.size() > URI_MAX_LENGTH) {
        return false;
    }
    // libvirt 支持 URI 别名，此处只过滤明确不适合作为参数的控制字节。
    return std::none_of(uri.begin(), uri.end(), [](unsigned char value) { return value < 0x20 || value == 0x7f; });
}

// 保留候选出现顺序和其余参数的原有顺序，不在解析阶段打开连接。
CreateConnectionArgs ParseCreateConnectionArgs(const std::vector<std::string> &args)
{
    CreateConnectionArgs result;
    result.argsWithoutConnection.reserve(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
        const auto &arg = args[i];
        // 参数终止符之后的内容按位置参数保留，不再解释为连接选项。
        if (arg == "--") {
            result.argsWithoutConnection.insert(result.argsWithoutConnection.end(), args.begin() + i, args.end());
            break;
        }
        if (arg == "--connect" || arg == "-c") {
            result.hasExplicitOption = true;
            // 缺值时保留空候选，同时不吞掉后续的其他选项。
            if (i + 1 < args.size() && !args[i + 1].empty() && args[i + 1].front() != '-') {
                result.candidates.push_back(args[++i]);
            } else {
                result.candidates.emplace_back();
            }
            continue;
        }
        if (arg.rfind("--connect=", 0) == 0) {
            result.hasExplicitOption = true;
            result.candidates.push_back(arg.substr(sizeof("--connect=") - 1));
            continue;
        }
        if (arg.rfind("-c", 0) == 0 && arg.size() > 2) {
            result.hasExplicitOption = true;
            result.candidates.push_back(arg.substr(2));
            continue;
        }
        result.argsWithoutConnection.push_back(arg);
    }
    return result;
}
} // namespace virtrust
