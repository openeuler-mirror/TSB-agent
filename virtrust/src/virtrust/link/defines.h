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

// 目的端首个请求仍在执行时通过 gRPC error_details 返回；源端只对这个精确标记延长轮询。
constexpr const char *MIGRATION_STEP_IN_PROGRESS_DETAIL = "virtrust.migration.step-in-progress";

// 两种源端删除动作各自使用相同的有界总尝试次数。
constexpr uint16_t DEFAULT_SOURCE_CLEANUP_MAX_ATTEMPTS = 3;
constexpr uint16_t MAX_SOURCE_CLEANUP_MAX_ATTEMPTS = 10;

// 节点 RPC 默认最多承受三次网络失败；目的端明确的“处理中”轮询不消耗该次数。
// 无论发生多少次轮询，整个阶段都受调用方的同一个期限约束。
constexpr uint16_t DEFAULT_RPC_RETRY_MAX_ATTEMPTS = 3;
constexpr uint16_t MAX_RPC_RETRY_MAX_ATTEMPTS = 10;
// 退避只影响重发间隔，不修改单次迁移的阶段期限；毫秒上限在配置入口校验。
constexpr uint16_t DEFAULT_RPC_RETRY_INITIAL_BACKOFF_MS = 100;
constexpr uint16_t MAX_RPC_RETRY_INITIAL_BACKOFF_MS = 1000;
constexpr uint16_t DEFAULT_RPC_RETRY_MAX_BACKOFF_MS = 1000;
constexpr uint16_t MAX_RPC_RETRY_MAX_BACKOFF_MS = 5000;

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
    // 仅控制源端节点间 RPC 的网络失败总尝试，不计目的端明确的“处理中”轮询。
    uint16_t rpcRetryMaxAttempts = DEFAULT_RPC_RETRY_MAX_ATTEMPTS;
    // 首次重发等待时间；后续按两倍递增并加抖动。
    uint16_t rpcRetryInitialBackoffMs = DEFAULT_RPC_RETRY_INITIAL_BACKOFF_MS;
    // 指数退避的基础时间上限；实际抖动后的等待时间可能略高于该值。
    uint16_t rpcRetryMaxBackoffMs = DEFAULT_RPC_RETRY_MAX_BACKOFF_MS;
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
