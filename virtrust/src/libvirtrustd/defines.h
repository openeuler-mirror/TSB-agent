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
constexpr std::string_view LIBVIRTRUSTD_CA_PATH = "ca-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_CERT_PATH = "server-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_SK_PATH = "server-sk.pem";
constexpr std::string_view LIBVIRTRUSTD_UDS_PATH = "/tmp/grpc.sock";
constexpr const char *VIRTRUSTD_LOGFILE_NAME = "/var/log/virtrustd.log";
// 节点实例锁目录不接受配置覆盖，避免不同配置启动多个守护进程。
constexpr const char *VIRTRUSTD_RUNTIME_DIRECTORY = "/run/virtrust";
constexpr uint16_t LIBVIRTRUSTD_SERVER_PORT = 5031;
} // namespace virtrust
