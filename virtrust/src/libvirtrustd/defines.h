/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace virtrust {
// 版本信息。
constexpr std::string_view LIBVIRTRUSTD_VERSION = "1.0.0";

// 默认配置。
constexpr std::string_view LIBVIRTRUSTD_SERVER_ADDR = "127.0.0.1";
// 与 RPM 示例配置保持一致；缺省证书路径也必须满足读取函数的绝对路径约束。
constexpr std::string_view LIBVIRTRUSTD_CA_PATH = "/etc/virtrust/certs/ca-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_CERT_PATH = "/etc/virtrust/certs/server-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_SK_PATH = "/etc/virtrust/certs/server-key.pem";
// 生产端点固定在 root 专用目录；与本地 API 客户端保持一致，不接受配置覆盖。
constexpr std::string_view LIBVIRTRUSTD_UDS_PATH = "/run/virtrust/rpc.sock";
constexpr const char *VIRTRUSTD_LOGFILE_NAME = "/var/log/virtrustd.log";
// 节点实例锁目录不接受配置覆盖，避免不同配置启动多个守护进程。
constexpr const char *VIRTRUSTD_RUNTIME_DIRECTORY = "/run/virtrust";
constexpr uint16_t LIBVIRTRUSTD_SERVER_PORT = 5031;
} // namespace virtrust
