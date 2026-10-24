/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "virtrust/api/defines.h"

namespace virtrust {
namespace protos {
class MigrationDiagnostic;
}

// 迁移结果仅描述已经取得的证据；未知结果不能解释成已经回滚。
enum class MigrationOutcome : uint32_t { Unknown = 0, Success = 1, FailedBeforeEffect = 2, Partial = 3 };
// 记录第一处错误发生在迁移数据流的哪个阶段；与错误来自哪一侧分别表达。
enum class MigrationStage : uint32_t {
    None = 0,
    Preflight = 1,
    Prepare = 2,
    KeyExchange = 3,
    Start = 4,
    LibvirtTransfer = 5,
    DataTransfer = 6,
    SourceCommit = 7,
    DestinationCommit = 8,
    SourceCleanup = 9,
    Uds = 10,
};
// 错误所在节点，不等同于发起请求的节点。
enum class MigrationSide : uint32_t { Unknown = 0, Source = 1, Destination = 2 };
// 失败的具体动作，供 CLI 诊断与人工排查，不用于自动回滚决策。
enum class MigrationOperation : uint32_t {
    None = 0,
    Validate = 1,
    AcquireAdmission = 2,
    ConnectLibvirt = 3,
    LookupDomain = 4,
    CheckIdentity = 5,
    VerifyCertificate = 6,
    VerifyReport = 7,
    ExchangeKey = 8,
    GetCipher = 9,
    ImportCipher = 10,
    CreateVRoot = 11,
    MigrateLibvirt = 12,
    NotifyTsb = 13,
    NotifyPeer = 14,
    RemoveVRoot = 15,
    UndefineDomain = 16,
    GetCertificate = 17,
    GetReport = 18,
    ExportKey = 19,
    GetDescription = 20,
};
// 标明原始错误码属于哪层；只有 TSB/libvirt 等确实给码时才设置 hasRawCode。
enum class MigrationErrorOrigin : uint32_t {
    Unknown = 0,
    Validation = 1,
    Tsb = 2,
    Libvirt = 3,
    Grpc = 4,
    Internal = 5,
};
// 位集只表示已取得成功确认的里程碑，不能由“未置位”推断远端没有执行。
enum class MigrationStep : uint32_t {
    LibvirtTransferred = 1U << 0,
    DestinationDataAccepted = 1U << 1,
    SourceTsbCommitted = 1U << 2,
    DestinationConfirmed = 1U << 3,
    SourceVRootRemoved = 1U << 4,
    SourceDefinitionUndefined = 1U << 5,
};

// 原始码只有在底层确实给出时才有效，不能用默认零伪装为成功。
struct MigrationError {
    MigrationStage stage = MigrationStage::None;
    MigrationSide side = MigrationSide::Unknown;
    MigrationOperation operation = MigrationOperation::None;
    MigrationErrorOrigin origin = MigrationErrorOrigin::Unknown;
    bool hasRawCode = false;
    int32_t rawCode = 0;
};

// rc 保留现有调用方分支语义；outcome 与确认步骤描述真实效果，不能只看 rc 判断残留。
struct MigrationResult {
    // 请求发送前生成的查询身份；有此 ID 不代表守护进程已接收或执行请求。
    std::string attemptId;
    // 保留 API 既有返回码；完整业务结论由 outcome 和已确认步骤补充。
    VirtrustRc rc = VirtrustRc::ERROR;
    MigrationOutcome outcome = MigrationOutcome::Unknown;
    // 第一处业务错误不被后续补偿错误覆盖。
    MigrationError primaryError;
    bool hasPrimaryError = false;
    // 每一位只在取得该步骤的成功确认后设置。
    uint32_t confirmedSteps = 0;
    // 清理或补偿失败按发生顺序追加，用于人工排查残留。
    std::vector<MigrationError> compensationErrors;
    // 未能确认远端或存在部分结果时要求人工核查，而非自动重发整个迁移。
    bool manualCheckRequired = true;
};

// 目的端本进程可查询的最终阶段状态；Unknown 不等于未执行。
enum class MigrationFinalState : uint8_t { Unknown, InProgress, CompletedSuccess, CompletedFailure };

// 手工/自动查询返回的快照；仅 CompletedFailure 可能附带目的端业务诊断。
struct MigrationFinalQueryResult {
    MigrationFinalState state = MigrationFinalState::Unknown;
    MigrationResult diagnostic;
    bool hasDiagnostic = false;
};

void ToProto(const MigrationResult &result, protos::MigrationDiagnostic *wire);
MigrationResult FromProto(const protos::MigrationDiagnostic &wire, VirtrustRc rc);

// 仅使用固定枚举名及底层数值码生成英文诊断，不包含证书、密钥或密文。
std::string FormatMigrationResult(const MigrationResult &result);

} // namespace virtrust
