/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "gtest/gtest.h"

#include <google/protobuf/descriptor.h>

#include <string>

#include "tsb_agent/tsb_agent.h"
#include "virtrust/link/migration_result.h"
#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {
namespace {

TEST(MigrationResultTest, PreservesPartialResultAcrossProtoRoundTrip)
{
    MigrationResult original;
    original.rc = VirtrustRc::ERROR;
    original.outcome = MigrationOutcome::Partial;
    original.primaryError = {MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::RemoveVRoot,
                             MigrationErrorOrigin::Tsb, true, ERR_FILE_LOCK};
    original.hasPrimaryError = true;
    original.confirmedSteps = static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
                              static_cast<uint32_t>(MigrationStep::DestinationConfirmed);

    protos::MigrationDiagnostic wire;
    ToProto(original, &wire);
    protos::MigrationDiagnostic parsed;
    ASSERT_TRUE(parsed.ParseFromString(wire.SerializeAsString()));
    const auto decoded = FromProto(parsed, VirtrustRc::ERROR);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Partial);
    EXPECT_TRUE(decoded.manualCheckRequired);
    ASSERT_TRUE(decoded.hasPrimaryError);
    EXPECT_EQ(decoded.primaryError.operation, MigrationOperation::RemoveVRoot);
    EXPECT_EQ(decoded.primaryError.rawCode, ERR_FILE_LOCK);
    EXPECT_EQ(decoded.confirmedSteps, original.confirmedSteps);
    EXPECT_TRUE(decoded.compensationErrors.empty());
}

TEST(MigrationResultTest, PreservesCompensationFailureWithoutReplacingPrimaryError)
{
    MigrationResult original;
    original.rc = VirtrustRc::ERROR;
    original.outcome = MigrationOutcome::Unknown;
    original.primaryError = {MigrationStage::DataTransfer, MigrationSide::Source, MigrationOperation::NotifyPeer,
                             MigrationErrorOrigin::Grpc, true, -1};
    original.hasPrimaryError = true;
    original.compensationErrors.push_back({MigrationStage::DataTransfer, MigrationSide::Destination,
                                           MigrationOperation::UndefineDomain, MigrationErrorOrigin::Libvirt, true, -1});

    protos::MigrationDiagnostic wire;
    ToProto(original, &wire);
    const auto decoded = FromProto(wire, VirtrustRc::ERROR);

    ASSERT_TRUE(decoded.hasPrimaryError);
    EXPECT_EQ(decoded.primaryError.operation, MigrationOperation::NotifyPeer);
    ASSERT_EQ(decoded.compensationErrors.size(), 1U);
    EXPECT_EQ(decoded.compensationErrors.front().operation, MigrationOperation::UndefineDomain);
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, RejectsContradictorySuccessDiagnostic)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_SUCCESS);
    wire.mutable_primary_error()->set_operation(protos::MIGRATION_OPERATION_REMOVE_VROOT);

    const auto decoded = FromProto(wire, VirtrustRc::ERROR);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Unknown);
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, SuccessWithoutConfirmedMilestonesBecomesUnknown)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_SUCCESS);

    const auto decoded = FromProto(wire, VirtrustRc::OK);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Unknown);
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, SuccessWithAllConfirmedMilestonesRemainsSuccess)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_SUCCESS);
    wire.set_confirmed_steps(static_cast<uint32_t>(MigrationStep::LibvirtTransferred) |
                             static_cast<uint32_t>(MigrationStep::DestinationDataAccepted) |
                             static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
                             static_cast<uint32_t>(MigrationStep::DestinationConfirmed) |
                             static_cast<uint32_t>(MigrationStep::SourceVRootRemoved) |
                             static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined));

    const auto decoded = FromProto(wire, VirtrustRc::OK);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Success);
    EXPECT_FALSE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, SuccessThatRequiresManualCheckBecomesUnknown)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_SUCCESS);
    wire.set_confirmed_steps(static_cast<uint32_t>(MigrationStep::LibvirtTransferred) |
                             static_cast<uint32_t>(MigrationStep::DestinationDataAccepted) |
                             static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
                             static_cast<uint32_t>(MigrationStep::DestinationConfirmed) |
                             static_cast<uint32_t>(MigrationStep::SourceVRootRemoved) |
                             static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined));
    wire.set_manual_check_required(true);

    const auto decoded = FromProto(wire, VirtrustRc::OK);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Unknown);
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, UnknownConfirmedStepBitIsNotReported)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_PARTIAL);
    wire.set_confirmed_steps(static_cast<uint32_t>(MigrationStep::DestinationConfirmed) | (1U << 30));

    const auto decoded = FromProto(wire, VirtrustRc::ERROR);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Unknown);
    EXPECT_EQ(decoded.confirmedSteps, static_cast<uint32_t>(MigrationStep::DestinationConfirmed));
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, FailedBeforeEffectWithConfirmedStepBecomesUnknown)
{
    protos::MigrationDiagnostic wire;
    wire.set_outcome(protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    wire.set_confirmed_steps(static_cast<uint32_t>(MigrationStep::LibvirtTransferred));

    const auto decoded = FromProto(wire, VirtrustRc::ERROR);

    EXPECT_EQ(decoded.outcome, MigrationOutcome::Unknown);
    EXPECT_TRUE(decoded.manualCheckRequired);
}

TEST(MigrationResultTest, ErrorClassificationUsesProtoEnums)
{
    const auto *descriptor = protos::MigrationErrorInfo::descriptor();
    for (const char *name : {"stage", "side", "operation", "origin"}) {
        const auto *field = descriptor->FindFieldByName(name);
        ASSERT_NE(field, nullptr);
        EXPECT_EQ(field->type(), google::protobuf::FieldDescriptor::TYPE_ENUM);
    }
}

TEST(MigrationResultTest, FormatsPartialFailureWithoutSensitivePayload)
{
    MigrationResult result;
    result.outcome = MigrationOutcome::Partial;
    result.primaryError = {MigrationStage::SourceCleanup, MigrationSide::Source,
                           MigrationOperation::RemoveVRoot, MigrationErrorOrigin::Tsb, true, ERR_FILE_LOCK};
    result.hasPrimaryError = true;
    result.manualCheckRequired = true;
    result.confirmedSteps = static_cast<uint32_t>(MigrationStep::DestinationConfirmed);

    const std::string message = FormatMigrationResult(result);
    EXPECT_NE(message.find("PARTIAL"), std::string::npos);
    EXPECT_NE(message.find("SOURCE_CLEANUP"), std::string::npos);
    EXPECT_NE(message.find("REMOVE_VROOT"), std::string::npos);
    EXPECT_NE(message.find("raw_code=7"), std::string::npos);
    EXPECT_NE(message.find("confirmed_steps=DESTINATION_CONFIRMED"), std::string::npos);
    EXPECT_NE(message.find("Manual verification required"), std::string::npos);
    EXPECT_NE(message.find("Do not retry automatically; verify both nodes first."), std::string::npos);
    EXPECT_EQ(message.find("cipher"), std::string::npos);
    EXPECT_EQ(message.find("certificate"), std::string::npos);
}

TEST(MigrationResultTest, FormatsZeroConfirmedStepsWithoutClaimingNoEffect)
{
    MigrationResult result;
    result.outcome = MigrationOutcome::Unknown;

    const std::string message = FormatMigrationResult(result);

    EXPECT_NE(message.find("confirmed_steps=NONE_CONFIRMED"), std::string::npos);
    EXPECT_NE(message.find("Do not retry automatically; verify both nodes first."), std::string::npos);
    EXPECT_EQ(message.find("NO_EFFECT"), std::string::npos);
}

TEST(MigrationResultTest, FormatsCompensationFailureSeparatelyFromPrimaryCause)
{
    MigrationResult result;
    result.primaryError = {MigrationStage::DataTransfer, MigrationSide::Source,
                           MigrationOperation::NotifyPeer, MigrationErrorOrigin::Grpc, false, 0};
    result.hasPrimaryError = true;
    result.compensationErrors.push_back({MigrationStage::DataTransfer, MigrationSide::Destination,
                                         MigrationOperation::UndefineDomain, MigrationErrorOrigin::Libvirt, true, -1});

    const std::string message = FormatMigrationResult(result);
    EXPECT_NE(message.find("stage=DATA_TRANSFER"), std::string::npos);
    EXPECT_NE(message.find("operation=NOTIFY_PEER"), std::string::npos);
    EXPECT_NE(message.find("compensation[0]"), std::string::npos);
    EXPECT_NE(message.find("operation=UNDEFINE_DOMAIN"), std::string::npos);
    EXPECT_NE(message.find("raw_code=-1"), std::string::npos);
}

} // namespace
} // namespace virtrust
