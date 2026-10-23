/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "virtrust/base/logger.h"

namespace virtrust {
enum class LinkRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

// 节点间 RPC 仅以 -1 表示未取得有效回复；非负值是已收到的业务 result。
constexpr int32_t RPC_TRANSPORT_FAILURE = -1;

// 两种源端删除动作各自使用相同的有界总尝试次数。
constexpr uint16_t DEFAULT_SOURCE_CLEANUP_MAX_ATTEMPTS = 3;
constexpr uint16_t MAX_SOURCE_CLEANUP_MAX_ATTEMPTS = 10;

struct LinkConfig {
    std::string caPath;
    std::string certPath;
    std::string skPath;
    std::string ip;
    std::string ipMask;
    uint16_t port = 0;
    std::string udsPath;
    // 源端可信资源和虚机定义各自的最大总尝试次数，缺省沿用普通取消定义的三次。
    uint16_t sourceCleanupMaxAttempts = DEFAULT_SOURCE_CLEANUP_MAX_ATTEMPTS;
};

class ConfigMgr {
public:
    static ConfigMgr &Instance()
    {
        static ConfigMgr instance;
        return instance;
    }
    void SetLinkConfig(const LinkConfig &config)
    {
        linkConfig_ = config;
    }
    LinkConfig GetLinkConfig()
    {
        return linkConfig_;
    }

private:
    LinkConfig linkConfig_;
};

struct MigrationConfig {
    std::string domainName;
    std::string uuid;
    std::string destUri;
    std::string localUri;
    unsigned int flags;
};

} // namespace virtrust
