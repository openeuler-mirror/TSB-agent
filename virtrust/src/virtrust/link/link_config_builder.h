/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "virtrust/link/defines.h"

namespace virtrust {

class LinkConfigBuilder {
public:
#define VIRTRUST_LINK_BUILDER_ADD(TYPE, NAME) \
    LinkConfigBuilder NAME(TYPE NAME)         \
    {                                         \
        config_.NAME = NAME;                  \
        return *this;                         \
    }

    VIRTRUST_LINK_BUILDER_ADD(const std::string &, caPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, udsPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, certPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, skPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, ip)
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, port)
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, sourceCleanupMaxAttempts)
    // 三个字段随守护进程配置复制到源端 RpcClient，不影响目的端服务监听配置。
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, rpcRetryMaxAttempts)
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, rpcRetryInitialBackoffMs)
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, rpcRetryMaxBackoffMs)

#undef VIRTRUST_LINK_BUILDER_ADD

    LinkConfig Build()
    {
        return config_;
    }

private:
    LinkConfig config_;
};

} // namespace virtrust
