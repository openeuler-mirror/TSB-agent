/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/link/migration_attempt_id.h"

#include <sys/random.h>

#include <cerrno>
#include <cstdint>
#include <stdexcept>

namespace virtrust {

std::string GenerateMigrationAttemptId()
{
    // 一次尝试使用 128 位系统随机数；短读继续补齐，信号中断仅重试读取。
    uint8_t random[16]{};
    size_t received = 0;
    while (received < sizeof(random)) {
        const auto count = getrandom(random + received, sizeof(random) - received, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("Failed to generate migration attempt ID");
        }
        received += static_cast<size_t>(count);
    }
    // 用固定长度小写十六进制表示，便于协议校验与日志定位；不传输原始二进制缓冲区。
    constexpr char digits[] = "0123456789abcdef";
    std::string result(32, '0');
    for (size_t index = 0; index < sizeof(random); ++index) {
        result[2 * index] = digits[random[index] >> 4];
        result[2 * index + 1] = digits[random[index] & 0x0f];
    }
    return result;
}

} // namespace virtrust
