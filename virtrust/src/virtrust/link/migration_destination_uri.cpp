/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/link/migration_destination_uri.h"

#include <string_view>

namespace virtrust {
namespace {

bool ParseDecimal(std::string_view text, unsigned int limit, bool canonical)
{
    if (text.empty() || (canonical && text.size() > 1 && text.front() == '0')) {
        return false;
    }
    unsigned int value = 0;
    for (const char digit : text) {
        if (digit < '0' || digit > '9') {
            return false;
        }
        value = value * 10 + static_cast<unsigned int>(digit - '0');
        if (value > limit) {
            return false;
        }
    }
    return true;
}

bool IsCanonicalIpv4(std::string_view host)
{
    for (unsigned int i = 0; i < 4; ++i) {
        const size_t dot = host.find('.');
        const std::string_view octet = dot == std::string_view::npos ? host : host.substr(0, dot);
        if (!ParseDecimal(octet, 255, true)) {
            return false;
        }
        if (i == 3) {
            return dot == std::string_view::npos;
        }
        if (dot == std::string_view::npos) {
            return false;
        }
        host.remove_prefix(dot + 1);
    }
    return false;
}

} // namespace

bool ParseMigrationDestinationUri(const std::string &uri, std::string &ipv4)
{
    ipv4.clear();
    constexpr std::string_view prefix = "qemu+tls://";
    constexpr std::string_view path = "/system";
    const std::string_view text(uri);
    if (text.size() <= prefix.size() + path.size() || text.substr(0, prefix.size()) != prefix ||
        text.substr(text.size() - path.size()) != path) {
        return false;
    }
    // 拒绝 authority 以外的路径、查询、片段等文本，避免 RPC 目标与 libvirt 目标分离。
    const std::string_view authority = text.substr(prefix.size(), text.size() - prefix.size() - path.size());
    const size_t colon = authority.find(':');
    const std::string_view host = authority.substr(0, colon);
    if (!IsCanonicalIpv4(host)) {
        return false;
    }
    if (colon != std::string_view::npos && !ParseDecimal(authority.substr(colon + 1), 65535, false)) {
        return false;
    }
    if (colon != std::string_view::npos && authority.substr(colon + 1).find_first_not_of('0') ==
        std::string_view::npos) {
        return false;
    }
    ipv4.assign(host.data(), host.size());
    return true;
}

} // namespace virtrust
