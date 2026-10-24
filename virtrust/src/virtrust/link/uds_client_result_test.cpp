/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>

#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_result.h"

namespace virtrust {
namespace {
class ReplyService final : public protos::MigrationService::Service {
public:
    protos::DomainMigraterReply reply;
    protos::QueryMigrationFinalResultReply queryReply;
    grpc::Status status;
    std::string expectedAttempt;

    grpc::Status DomainMigrate(grpc::ServerContext *, const protos::DomainMigraterRequest *request,
                               protos::DomainMigraterReply *response) override
    {
        if (!expectedAttempt.empty()) {
            EXPECT_EQ(request->attempt_id(), expectedAttempt);
        }
        *response = reply;
        return status;
    }

    grpc::Status DomainQueryMigrationFinalResult(grpc::ServerContext *,
        const protos::QueryMigrationFinalResultRequest *request,
        protos::QueryMigrationFinalResultReply *response) override
    {
        EXPECT_EQ(request->uuid(), "12345678-1234-1234-1234-123456789001");
        EXPECT_EQ(request->attempt_id(), "0123456789abcdef0123456789abcdef");
        EXPECT_EQ(request->dest_uri(), "qemu+tls://192.168.1.100/system");
        *response = queryReply;
        return status;
    }
};

class UdsClientResultTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-uds-result-XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        directory_ = created;
        config_.udsPath = directory_ + "/rpc.sock";
    }

    void TearDown() override
    {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
        EXPECT_FALSE(error) << error.message();
    }

    void StartServer()
    {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("unix:" + config_.udsPath, grpc::InsecureServerCredentials());
        builder.RegisterService(&service_);
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
    }

    LinkConfig config_;
    ReplyService service_;
    std::unique_ptr<grpc::Server> server_;
    std::string directory_;
};

constexpr uint32_t AllConfirmedSteps()
{
    return static_cast<uint32_t>(MigrationStep::LibvirtTransferred) |
           static_cast<uint32_t>(MigrationStep::DestinationDataAccepted) |
           static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
           static_cast<uint32_t>(MigrationStep::DestinationConfirmed) |
           static_cast<uint32_t>(MigrationStep::SourceVRootRemoved) |
           static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined);
}

TEST_F(UdsClientResultTest, BusinessReplyPreservesPartialDiagnostic)
{
    MigrationResult expected;
    expected.rc = VirtrustRc::ERROR;
    expected.outcome = MigrationOutcome::Partial;
    expected.primaryError = {MigrationStage::SourceCleanup, MigrationSide::Source,
                             MigrationOperation::RemoveVRoot, MigrationErrorOrigin::Tsb, true, 7};
    expected.hasPrimaryError = true;
    expected.confirmedSteps = static_cast<uint32_t>(MigrationStep::DestinationConfirmed);
    expected.manualCheckRequired = true;
    service_.reply.set_result(static_cast<uint32_t>(expected.rc));
    service_.reply.set_attempt_id("0123456789abcdef0123456789abcdef");
    ToProto(expected, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, expected.rc);
    EXPECT_EQ(actual.outcome, expected.outcome);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.operation, expected.primaryError.operation);
    EXPECT_EQ(actual.primaryError.rawCode, expected.primaryError.rawCode);
    EXPECT_EQ(actual.confirmedSteps, expected.confirmedSteps);
    EXPECT_TRUE(actual.manualCheckRequired);
    EXPECT_EQ(actual.attemptId, "0123456789abcdef0123456789abcdef");
}

TEST_F(UdsClientResultTest, RejectsMalformedAttemptIdFromUdsReply)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    service_.reply.set_attempt_id("malformed\ntext");
    MigrationResult expected;
    expected.outcome = MigrationOutcome::FailedBeforeEffect;
    expected.manualCheckRequired = false;
    ToProto(expected, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    EXPECT_TRUE(client.DomainMigrate(MigrationConfig{}).attemptId.empty());
}

TEST_F(UdsClientResultTest, ReadOnlyManualQueryReturnsRecordedState)
{
    service_.queryReply.set_state(protos::FINAL_RESULT_COMPLETED_SUCCESS);
    ASSERT_NO_FATAL_FAILURE(StartServer());
    UdsClient client(config_);
    const auto result = client.QueryMigrationFinalResult(
        "12345678-1234-1234-1234-123456789001", "qemu+tls://192.168.1.100/system",
        "0123456789abcdef0123456789abcdef");
    EXPECT_EQ(result.state, MigrationFinalState::CompletedSuccess);
}

TEST_F(UdsClientResultTest, TransportFailureIgnoresSuccessfulLookingReply)
{
    // 服务端虽填了成功的 protobuf，gRPC 状态失败就没有可采信的业务回复。
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    MigrationResult misleading;
    misleading.rc = VirtrustRc::OK;
    misleading.outcome = MigrationOutcome::Success;
    misleading.manualCheckRequired = false;
    ToProto(misleading, service_.reply.mutable_diagnostic());
    service_.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected transport failure");
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.stage, MigrationStage::Uds);
    EXPECT_EQ(actual.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(actual.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(actual.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_FALSE(actual.primaryError.hasRawCode);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, TransportFailurePreservesCallerAttemptForManualCheck)
{
    service_.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected transport failure");
    ASSERT_NO_FATAL_FAILURE(StartServer());
    MigrationConfig migration{};
    migration.attemptId = "0123456789abcdef0123456789abcdef";
    service_.expectedAttempt = migration.attemptId;
    UdsClient client(config_);
    const auto result = client.DomainMigrate(migration);
    EXPECT_EQ(result.outcome, MigrationOutcome::Unknown);
    EXPECT_EQ(result.attemptId, migration.attemptId);
}

TEST_F(UdsClientResultTest, RejectsReplyForDifferentAttempt)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    service_.reply.set_attempt_id("fedcba9876543210fedcba9876543210");
    MigrationResult completed;
    completed.rc = VirtrustRc::OK;
    completed.outcome = MigrationOutcome::Success;
    completed.confirmedSteps = AllConfirmedSteps();
    completed.manualCheckRequired = false;
    ToProto(completed, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());
    MigrationConfig migration{};
    migration.attemptId = "0123456789abcdef0123456789abcdef";
    UdsClient client(config_);
    const auto result = client.DomainMigrate(migration);
    EXPECT_EQ(result.outcome, MigrationOutcome::Unknown);
    EXPECT_EQ(result.attemptId, migration.attemptId);
}

TEST_F(UdsClientResultTest, MissingDiagnosticIsNotSuccessfulMigration)
{
    // 当前协议要求结构化诊断；只有 result=0 的空回复不足以证明迁移完成。
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.stage, MigrationStage::Uds);
    EXPECT_EQ(actual.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, UnknownOutcomeCannotUseSuccessfulBusinessCode)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    MigrationResult conflicting;
    conflicting.rc = VirtrustRc::OK;
    conflicting.outcome = MigrationOutcome::Unknown;
    conflicting.primaryError = {MigrationStage::SourceCommit, MigrationSide::Source,
                                MigrationOperation::NotifyTsb, MigrationErrorOrigin::Tsb, true, 7};
    conflicting.hasPrimaryError = true;
    ToProto(conflicting, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.stage, MigrationStage::SourceCommit);
    EXPECT_EQ(actual.primaryError.rawCode, 7);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, FailureWithoutPrimaryCauseGetsUdsFallback)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    service_.reply.mutable_diagnostic()->set_outcome(protos::MIGRATION_OUTCOME_UNKNOWN);
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.stage, MigrationStage::Uds);
    EXPECT_EQ(actual.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(actual.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, UnknownNumericBusinessCodeRequiresManualCheck)
{
    service_.reply.set_result(99);
    service_.reply.mutable_diagnostic()->set_outcome(protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, BusyWithConfirmedEffectCannotMaskPartialFailure)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::BUSY));
    MigrationResult conflicting;
    conflicting.outcome = MigrationOutcome::Partial;
    conflicting.confirmedSteps = static_cast<uint32_t>(MigrationStep::DestinationConfirmed);
    conflicting.primaryError = {MigrationStage::SourceCleanup, MigrationSide::Source,
                                MigrationOperation::RemoveVRoot, MigrationErrorOrigin::Tsb, true, 7};
    conflicting.hasPrimaryError = true;
    ToProto(conflicting, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    EXPECT_EQ(actual.confirmedSteps, conflicting.confirmedSteps);
    ASSERT_TRUE(actual.hasPrimaryError);
    EXPECT_EQ(actual.primaryError.operation, MigrationOperation::RemoveVRoot);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, ValidBusyStillMeansMigrationNeverStarted)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::BUSY));
    MigrationResult expected;
    expected.outcome = MigrationOutcome::FailedBeforeEffect;
    expected.manualCheckRequired = false;
    expected.primaryError = {MigrationStage::Preflight, MigrationSide::Source,
                             MigrationOperation::AcquireAdmission, MigrationErrorOrigin::Validation, false, 0};
    expected.hasPrimaryError = true;
    ToProto(expected, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::BUSY);
    EXPECT_EQ(actual.outcome, MigrationOutcome::FailedBeforeEffect);
    EXPECT_FALSE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, SuccessCodeWithBeforeEffectDiagnosticIsUnknown)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    MigrationResult conflicting;
    conflicting.outcome = MigrationOutcome::FailedBeforeEffect;
    conflicting.primaryError = {MigrationStage::Preflight, MigrationSide::Source,
                                MigrationOperation::Validate, MigrationErrorOrigin::Validation, false, 0};
    conflicting.hasPrimaryError = true;
    ToProto(conflicting, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::ERROR);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Unknown);
    EXPECT_TRUE(actual.manualCheckRequired);
}

TEST_F(UdsClientResultTest, FullSuccessWithAllMilestonesIsPreserved)
{
    service_.reply.set_result(static_cast<uint32_t>(VirtrustRc::OK));
    MigrationResult expected;
    expected.outcome = MigrationOutcome::Success;
    expected.manualCheckRequired = false;
    expected.confirmedSteps = AllConfirmedSteps();
    ToProto(expected, service_.reply.mutable_diagnostic());
    ASSERT_NO_FATAL_FAILURE(StartServer());

    UdsClient client(config_);
    const MigrationResult actual = client.DomainMigrate(MigrationConfig{});
    EXPECT_EQ(actual.rc, VirtrustRc::OK);
    EXPECT_EQ(actual.outcome, MigrationOutcome::Success);
    EXPECT_EQ(actual.confirmedSteps, expected.confirmedSteps);
    EXPECT_FALSE(actual.manualCheckRequired);
}
} // namespace
} // namespace virtrust
