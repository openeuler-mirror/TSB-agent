/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <string>

#include "virtrust/link/defines.h"
#include "virtrust/link/migration_result.h"

#include "virtrust/link/proto/migrate.grpc.pb.h"

#ifdef VIRTRUST_MOCK
#include "virtrust/link/mock/grpc_client_mock.h"
#endif

namespace virtrust {

#ifdef VIRTRUST_MOCK
// Use Mock implementation in fuzz mode
using UdsClient = UdsClientMock;
using RpcClient = RpcClientMock;
#else
// CLI 和公开 API 访问本机守护进程；不直接连接目的节点。
class UdsClient {
public:
    explicit UdsClient(LinkConfig config);

    MigrationResult DomainMigrate(const MigrationConfig &config);

    MigrationFinalQueryResult QueryMigrationFinalResult(const std::string &uuid, const std::string &destUri,
                                                       const std::string &attemptId);

private:
    LinkConfig config_;
};

// 源端守护进程访问目的端守护进程；调用者必须区分传输失败和业务回复。
class RpcClient {
public:
    explicit RpcClient(LinkConfig config);

    int32_t PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest &request,
                             protos::PrepareMigReply *response);

    // 2: 交换公钥
    int32_t ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                protos::EXchangePkAndReportReply *response);

    // 3: 开始迁移
    int32_t StartMigration(uint32_t timeout, const protos::StartMigRequest &request, protos::StartMigReply *response);

    // 4：迁移虚机密码资源
    int32_t SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                             protos::VRsourceInfoReply *response);

    // 5: 通知迁移结果
    int32_t NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                  protos::MigrateResultReply *response);

    // 自动核查会在同一总期限内轮询 IN_PROGRESS；返回 -1 表示未取得最终可信回复。
    int32_t QueryMigrationFinalResult(uint32_t timeout, const protos::QueryMigrationFinalResultRequest &request,
                                      protos::QueryMigrationFinalResultReply *response);

    // 人工查询只读取一次目的端状态；IN_PROGRESS 直接交给调用方展示。
    int32_t QueryMigrationFinalResultOnce(uint32_t timeout, const protos::QueryMigrationFinalResultRequest &request,
                                          protos::QueryMigrationFinalResultReply *response);

private:
    LinkConfig config_;
};
#endif

} // namespace virtrust
