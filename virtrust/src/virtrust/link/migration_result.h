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
enum class MigrationSide : uint32_t { Unknown = 0, Source = 1, Destination = 2 };
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
enum class MigrationErrorOrigin : uint32_t {
    Unknown = 0,
    Validation = 1,
    Tsb = 2,
    Libvirt = 3,
    Grpc = 4,
    Internal = 5,
};
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
    VirtrustRc rc = VirtrustRc::ERROR;
    MigrationOutcome outcome = MigrationOutcome::Unknown;
    MigrationError primaryError;
    bool hasPrimaryError = false;
    uint32_t confirmedSteps = 0;
    std::vector<MigrationError> compensationErrors;
    bool manualCheckRequired = true;
};

void ToProto(const MigrationResult &result, protos::MigrationDiagnostic *wire);
MigrationResult FromProto(const protos::MigrationDiagnostic &wire, VirtrustRc rc);

// 仅使用固定枚举名及底层数值码生成英文诊断，不包含证书、密钥或密文。
std::string FormatMigrationResult(const MigrationResult &result);

} // namespace virtrust
