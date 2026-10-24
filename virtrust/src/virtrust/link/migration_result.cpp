/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/link/migration_result.h"

#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {
namespace {

constexpr uint32_t kAllConfirmedSteps = static_cast<uint32_t>(MigrationStep::LibvirtTransferred) |
    static_cast<uint32_t>(MigrationStep::DestinationDataAccepted) |
    static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
    static_cast<uint32_t>(MigrationStep::DestinationConfirmed) |
    static_cast<uint32_t>(MigrationStep::SourceVRootRemoved) |
    static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined);

template <typename Enum>
Enum DecodeEnum(uint32_t value, uint32_t maximum, Enum fallback)
{
    return value <= maximum ? static_cast<Enum>(value) : fallback;
}

void ToProtoError(const MigrationError &error, protos::MigrationErrorInfo *wire)
{
    wire->set_stage(static_cast<protos::MigrationStageCode>(error.stage));
    wire->set_side(static_cast<protos::MigrationSideCode>(error.side));
    wire->set_operation(static_cast<protos::MigrationOperationCode>(error.operation));
    wire->set_origin(static_cast<protos::MigrationErrorOriginCode>(error.origin));
    wire->set_has_raw_code(error.hasRawCode);
    if (error.hasRawCode) {
        wire->set_raw_code(error.rawCode);
    }
}

MigrationError FromProtoError(const protos::MigrationErrorInfo &wire)
{
    MigrationError error;
    error.stage = DecodeEnum(wire.stage(), static_cast<uint32_t>(MigrationStage::Uds), MigrationStage::None);
    error.side = DecodeEnum(wire.side(), static_cast<uint32_t>(MigrationSide::Destination), MigrationSide::Unknown);
    error.operation = DecodeEnum(wire.operation(), static_cast<uint32_t>(MigrationOperation::GetDescription),
                                 MigrationOperation::None);
    error.origin = DecodeEnum(wire.origin(), static_cast<uint32_t>(MigrationErrorOrigin::Internal),
                              MigrationErrorOrigin::Unknown);
    error.hasRawCode = wire.has_raw_code();
    error.rawCode = error.hasRawCode ? wire.raw_code() : 0;
    return error;
}

const char *OutcomeName(MigrationOutcome value)
{
    switch (value) {
        case MigrationOutcome::Success: return "SUCCESS";
        case MigrationOutcome::FailedBeforeEffect: return "FAILED_BEFORE_EFFECT";
        case MigrationOutcome::Partial: return "PARTIAL";
        default: return "UNKNOWN";
    }
}

const char *StageName(MigrationStage value)
{
    switch (value) {
        case MigrationStage::Preflight: return "PREFLIGHT";
        case MigrationStage::Prepare: return "PREPARE";
        case MigrationStage::KeyExchange: return "KEY_EXCHANGE";
        case MigrationStage::Start: return "START";
        case MigrationStage::LibvirtTransfer: return "LIBVIRT_TRANSFER";
        case MigrationStage::DataTransfer: return "DATA_TRANSFER";
        case MigrationStage::SourceCommit: return "SOURCE_COMMIT";
        case MigrationStage::DestinationCommit: return "DESTINATION_COMMIT";
        case MigrationStage::SourceCleanup: return "SOURCE_CLEANUP";
        case MigrationStage::Uds: return "UDS";
        default: return "UNKNOWN";
    }
}

const char *SideName(MigrationSide value)
{
    switch (value) {
        case MigrationSide::Source: return "SOURCE";
        case MigrationSide::Destination: return "DESTINATION";
        default: return "UNKNOWN";
    }
}

const char *OperationName(MigrationOperation value)
{
    switch (value) {
        case MigrationOperation::Validate: return "VALIDATE";
        case MigrationOperation::AcquireAdmission: return "ACQUIRE_ADMISSION";
        case MigrationOperation::ConnectLibvirt: return "CONNECT_LIBVIRT";
        case MigrationOperation::LookupDomain: return "LOOKUP_DOMAIN";
        case MigrationOperation::CheckIdentity: return "CHECK_IDENTITY";
        case MigrationOperation::VerifyCertificate: return "VERIFY_CERTIFICATE";
        case MigrationOperation::VerifyReport: return "VERIFY_REPORT";
        case MigrationOperation::ExchangeKey: return "EXCHANGE_KEY";
        case MigrationOperation::GetCipher: return "GET_CIPHER";
        case MigrationOperation::ImportCipher: return "IMPORT_CIPHER";
        case MigrationOperation::CreateVRoot: return "CREATE_VROOT";
        case MigrationOperation::MigrateLibvirt: return "MIGRATE_LIBVIRT";
        case MigrationOperation::NotifyTsb: return "NOTIFY_TSB";
        case MigrationOperation::NotifyPeer: return "NOTIFY_PEER";
        case MigrationOperation::RemoveVRoot: return "REMOVE_VROOT";
        case MigrationOperation::UndefineDomain: return "UNDEFINE_DOMAIN";
        case MigrationOperation::GetCertificate: return "GET_CERTIFICATE";
        case MigrationOperation::GetReport: return "GET_REPORT";
        case MigrationOperation::ExportKey: return "EXPORT_KEY";
        case MigrationOperation::GetDescription: return "GET_DESCRIPTION";
        default: return "UNKNOWN";
    }
}

const char *OriginName(MigrationErrorOrigin value)
{
    switch (value) {
        case MigrationErrorOrigin::Validation: return "VALIDATION";
        case MigrationErrorOrigin::Tsb: return "TSB";
        case MigrationErrorOrigin::Libvirt: return "LIBVIRT";
        case MigrationErrorOrigin::Grpc: return "GRPC";
        case MigrationErrorOrigin::Internal: return "INTERNAL";
        default: return "UNKNOWN";
    }
}

void AppendConfirmedSteps(uint32_t steps, std::string &message)
{
    struct NamedStep {
        MigrationStep step;
        const char *name;
    };
    constexpr NamedStep names[] = {
        {MigrationStep::LibvirtTransferred, "LIBVIRT_TRANSFERRED"},
        {MigrationStep::DestinationDataAccepted, "DESTINATION_DATA_ACCEPTED"},
        {MigrationStep::SourceTsbCommitted, "SOURCE_TSB_COMMITTED"},
        {MigrationStep::DestinationConfirmed, "DESTINATION_CONFIRMED"},
        {MigrationStep::SourceVRootRemoved, "SOURCE_VROOT_REMOVED"},
        {MigrationStep::SourceDefinitionUndefined, "SOURCE_DEFINITION_UNDEFINED"},
    };
    // 仅展示已确认的已知位；没有位只表示没有取得成功回复，不表示业务一定未执行。
    message += ", confirmed_steps=";
    bool hasConfirmedStep = false;
    for (const auto &entry : names) {
        if ((steps & static_cast<uint32_t>(entry.step)) == 0) {
            continue;
        }
        if (hasConfirmedStep) {
            message += "|";
        }
        message += entry.name;
        hasConfirmedStep = true;
    }
    if (!hasConfirmedStep) {
        message += "NONE_CONFIRMED";
    }
}

} // namespace

void ToProto(const MigrationResult &result, protos::MigrationDiagnostic *wire)
{
    // 数值业务码仍由各 reply.result 传递；这里只序列化诊断，避免两份结果相互覆盖。
    if (wire == nullptr) {
        return;
    }
    wire->Clear();
    wire->set_outcome(static_cast<protos::MigrationOutcomeCode>(result.outcome));
    if (result.hasPrimaryError) {
        ToProtoError(result.primaryError, wire->mutable_primary_error());
    }
    wire->set_confirmed_steps(result.confirmedSteps);
    for (const auto &error : result.compensationErrors) {
        ToProtoError(error, wire->add_compensation_errors());
    }
    wire->set_manual_check_required(result.manualCheckRequired || result.outcome == MigrationOutcome::Partial ||
                                    result.outcome == MigrationOutcome::Unknown);
}

MigrationResult FromProto(const protos::MigrationDiagnostic &wire, VirtrustRc rc)
{
    // 将业务码与诊断重新合并；缺省 outcome 为 UNKNOWN，不能从空诊断推断成功。
    MigrationResult result;
    result.rc = rc;
    result.outcome = DecodeEnum(static_cast<uint32_t>(wire.outcome()), static_cast<uint32_t>(MigrationOutcome::Partial),
                                MigrationOutcome::Unknown);
    result.hasPrimaryError = wire.has_primary_error();
    if (result.hasPrimaryError) {
        result.primaryError = FromProtoError(wire.primary_error());
    }
    // 只保留当前协议定义的成功里程碑；未知位不能作为业务完成证据展示。
    const bool hasUnknownSteps = (wire.confirmed_steps() & ~kAllConfirmedSteps) != 0;
    result.confirmedSteps = wire.confirmed_steps() & kAllConfirmedSteps;
    for (const auto &error : wire.compensation_errors()) {
        result.compensationErrors.push_back(FromProtoError(error));
    }
    result.manualCheckRequired = wire.manual_check_required() || result.outcome == MigrationOutcome::Partial ||
                                 result.outcome == MigrationOutcome::Unknown;
    // 回复中的“成功”若与业务结果或错误明细冲突，不得作为成功交给调用方。
    if (result.outcome == MigrationOutcome::Success &&
        (rc != VirtrustRc::OK || result.hasPrimaryError || !result.compensationErrors.empty() ||
         result.manualCheckRequired ||
         result.confirmedSteps != kAllConfirmedSteps)) {
        result.outcome = MigrationOutcome::Unknown;
        result.manualCheckRequired = true;
    }
    if (hasUnknownSteps || (result.outcome == MigrationOutcome::FailedBeforeEffect &&
                            (result.confirmedSteps != 0 || !result.compensationErrors.empty()))) {
        result.outcome = MigrationOutcome::Unknown;
        result.manualCheckRequired = true;
    }
    return result;
}

std::string FormatMigrationResult(const MigrationResult &result)
{
    // 面向 CLI 只输出固定分类名和数值码，不拼接网络回复中的可信载荷。
    if (result.rc == VirtrustRc::OK && result.outcome == MigrationOutcome::Success) {
        return "Migration succeeded.";
    }
    std::string message = "Migration failed: outcome=";
    message += OutcomeName(result.outcome);
    if (result.hasPrimaryError) {
        const auto &error = result.primaryError;
        message += ", stage=";
        message += StageName(error.stage);
        message += ", side=";
        message += SideName(error.side);
        message += ", operation=";
        message += OperationName(error.operation);
        message += ", origin=";
        message += OriginName(error.origin);
        if (error.hasRawCode) {
            message += ", raw_code=" + std::to_string(error.rawCode);
        }
    }
    AppendConfirmedSteps(result.confirmedSteps, message);
    message += ".";
    for (size_t i = 0; i < result.compensationErrors.size(); ++i) {
        const auto &error = result.compensationErrors[i];
        message += " compensation[" + std::to_string(i) + "]: stage=";
        message += StageName(error.stage);
        message += ", side=";
        message += SideName(error.side);
        message += ", operation=";
        message += OperationName(error.operation);
        message += ", origin=";
        message += OriginName(error.origin);
        if (error.hasRawCode) {
            message += ", raw_code=" + std::to_string(error.rawCode);
        }
        message += ".";
    }
    if (result.manualCheckRequired || result.outcome == MigrationOutcome::Unknown ||
        result.outcome == MigrationOutcome::Partial) {
        message += " Manual verification required.";
        message += " Do not retry automatically; verify both nodes first.";
        // 最终通知无回复不代表目的端失败；只对这一明确的传输不确定场景追加专门提示。
        if (result.outcome == MigrationOutcome::Unknown && result.hasPrimaryError &&
            result.primaryError.stage == MigrationStage::DestinationCommit &&
            result.primaryError.side == MigrationSide::Source &&
            result.primaryError.operation == MigrationOperation::NotifyPeer &&
            result.primaryError.origin == MigrationErrorOrigin::Grpc) {
            message += " Destination may have committed despite the missing final reply.";
        }
    }
    return message;
}

} // namespace virtrust
