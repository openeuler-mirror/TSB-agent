// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace virtrust {

constexpr std::string_view VIRTRUST_DEFAULT_URI = "qemu:///session";
// 迁移独占资格只保护当前节点，源连接不能指向其他节点或依赖隐式默认连接。
constexpr bool IsLocalMigrationSourceUri(std::string_view uri) noexcept
{
    return uri == "qemu:///system" || uri == "qemu:///session";
}
// 本地客户端与守护进程使用同一固定端点；父目录由守护进程按 root 专用策略管理。
constexpr std::string_view UDS_PATH = "/run/virtrust/rpc.sock";

enum class VirtrustRc : uint32_t {
    OK = 0,
    ERROR = 1,
    CHECK_FAILED = 2,
    INCONSISTENT_RESOURCE = 3,
    // 节点准入被其他操作占用，本次变更业务尚未开始；不在接口内部自动重试。
    BUSY = 4,
};

enum DomainUndefineFlags {
    DOMAIN_UNDEFINE_NVRAM = (1 << 2),
    DOMAIN_UNDEFINE_KEEP_NVRAM = (1 << 3),
};

// 可组合 如LIST_DOMAINS_ACTIVE|LIST_DOMAINS_INACTIVE
enum DomainListFlags {
    LIST_DOMAINS_ACTIVE = (1 << 0),
    LIST_DOMAINS_INACTIVE = (1 << 1),
};

enum DomainStartFlags {
    DOMAIN_START_NONE = 0,
};

enum DomainDestroyFlags {
    DOMAIN_DESTROY_NONE = 0,
};

struct DomainInfo {
    std::string domainName;
    unsigned char state;        //  the running state, one of virDomainState
    unsigned long maxMem;       //  the maximum memory in KBytes allowed
    unsigned long memory;       //   the memory in KBytes used by the domain
    unsigned short nrVirtCpu;   //   the number of virtual CPUs for the domain
    unsigned long long cpuTime; //  the CPU time used in nanoseconds
};

enum DomainMigrateFlags {
    MIGRATE_UNDEFINE_SOURCE = (1 << 4), // Undefine the domain on the source host once migration successfully finishes.
};
} // namespace virtrust
