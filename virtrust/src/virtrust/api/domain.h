// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "virtrust/api/context.h"
#include "virtrust/api/defines.h"
#include "virtrust/link/migration_result.h"

namespace virtrust {
// 调用方必须保持传入的 ConnCtx 及其 unique_ptr 在整个同步 API 调用期间有效，
// 包括等待节点准入和旧业务锁的时间；不得在其他线程并发 reset、移动或销毁。
// 普通变更入口（Create/Destroy/Start/Undefine）要求 root，包括 only-tsb 分支。
// 不要求守护进程已启动；节点准入竞争返回 BUSY，权限或准入故障返回 ERROR。
// 调用方应以 rc != OK 判断失败；普通操作之间仍等待旧业务锁，不保证迁移公平性。
/**
 * 创建虚拟机
 * @param conn 连接参数
 * @param args 参数 参考virt-install --help
 * 名称字段必须指定。arg[0]为virt-install的路径 如：、usr/bin/virt-install
 * @return VirtrustRc
 */
VirtrustRc DomainCreate(const std::unique_ptr<ConnCtx> &conn, const std::vector<std::string> &args);

/**
 * 停止虚拟机
 * @param conn 连接参数
 * @param flags 见DomainDestroyFlags中的选项
 * @param domainName 虚拟机名称，isOnlyTsb为true时只停止tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只停止tsb资源，为true时只停止tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainDestroy(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags,
                         bool isOnlyTsb = false);

/**
 * 迁移虚拟机
 * @param conn 连接参数
 * @param flags 目前仅支持MIGRATE_UNDEFINE_SOURCE，删除源端虚拟机
 * @param domainName 虚拟机名称
 * @param destUri 目的端地址 格式为<protocol>://<hostip>/<path> 如qemu+tls://7.7.7.7/system
 * API 预检查仅用于构造请求；源端守护进程持独占资格后会复核虚机状态和 UUID。
 * 守护进程准入竞争返回 BUSY；API 不跨 UDS 调用持旧业务锁。
 * @return 迁移专用结果，包含业务码和失败阶段
 */
MigrationResult DomainMigrate(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                              const std::string &destUri, unsigned int flags = MIGRATE_UNDEFINE_SOURCE);

// 只读查询目的节点已记录的最终通知；UNKNOWN 不能证明迁移失败或可以重试。
MigrationFinalQueryResult DomainQueryMigrationFinalResult(const std::string &uuid, const std::string &destUri,
                                                         const std::string &attemptId);

/**
 * 启动虚拟机
 * @param conn 连接参数
 * @param flags 见DomainStartFlags中的选项
 * @param domainName 虚拟机名称，isOnlyTsb为true时只启动tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只启动tsb资源，为true时只启动tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainStart(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags,
                       bool isOnlyTsb = false);

/**
 * 删除虚拟机
 * @param conn 连接参数
 * @param flags 默认为0（适用于不产生nvram文件时，其他值
 * 见DomainUndefineFlags,DOMAIN_UNDEFINE_NVRAM和DOMAIN_UNDEFINE_KEEP_NVRAM仅支持同一时间指定一种
 * @param domainName 虚拟机名称，isOnlyTsb为true时只更新tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只删除tsb资源，为true时只删除tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainUndefine(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags = 0,
                          bool isOnlyTsb = false);

/**
 * 展示虚拟机
 * @param conn 连接参数
 * @param flags
 * 见DomainListFlag选项，可组合LIST_DOMAINS_ACTIVE|LIST_DOMAINS_INACTIVE
 * @param domainInfos 查询到的虚拟机信息
 * @param printErrToCli
 * 是否屏显tsb资源和libvirt资源不一致的错误信息，如果libvirt有但是tsb没有不会屏显，日志会有warn日志
 * @param failure 可选的迁移预检查错误输出；普通调用方无需传入
 * @return VirtrustRc
 */
VirtrustRc DomainList(const std::unique_ptr<ConnCtx> &conn, unsigned int flags,
                      std::unordered_map<std::string, DomainInfo> &domainInfos, bool printErrToCli = false,
                      MigrationError *failure = nullptr);
} // namespace virtrust
