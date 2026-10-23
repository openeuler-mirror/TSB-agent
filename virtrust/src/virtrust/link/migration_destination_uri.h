/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <string>

namespace virtrust {

// 只接受本业务支持的 libvirt 目的 URI 子集，并返回与其 authority 相同的节点间通信 IP。
bool ParseMigrationDestinationUri(const std::string &uri, std::string &ipv4);

} // namespace virtrust
