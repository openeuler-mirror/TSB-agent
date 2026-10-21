/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "virtrust/api/defines.h"
#include "virtrust/base/logger.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/link/migration_service_impl.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
namespace {
struct DestinationTestState {
    std::string directory;
    std::string expectedOutstandingUuid;
    bool failPrepare = false;
    bool useRealPrepare = false;
    bool throwOnPrepare = false;
    bool throwOnStart = false;
    bool throwOnAcquire = false;
    bool useRealClientPrepare = false;
    // 在源端同步 Prepare 调用尚未返回时，确定性触发会话阶段超时。
    bool expireSourceDuringPrepare = false;
    bool captureTimers = false;
    bool failCipherImport = false;
    bool acceptSuccessNotification = false;
    bool probeAtCleanup = false;
    bool cleanupProbeRan = false;
    int cipherImportCalls = 0;
    int getReportCalls = 0;
    int successNotificationCalls = 0;
    MigrateSessionRc cleanupProbeResult = MigrateSessionRc::OK;
    int clientPrepareCalls = 0;
    int clientNotifyCalls = 0;
    uint32_t clientPrepareResult = 0;
    std::vector<std::function<void()>> timerCallbacks;
};

DestinationTestState &State()
{
    static DestinationTestState state;
    return state;
}

class DestinationMigrationAdmissionTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // 安全目录检查要求 / 属主为 root；某些隔离沙箱会虚拟化为 nobody，无法运行真实文件锁测试。
        struct stat rootInfo {};
        ASSERT_EQ(stat("/", &rootInfo), 0);
        if (rootInfo.st_uid != 0) {
            GTEST_SKIP() << "Root directory owner is virtualized; trusted-path admission cannot be tested";
        }
        // CI 工作区可能允许组写入；仅当 /tmp 满足生产目录策略时才优先使用它。
        struct stat tempInfo {};
        const bool trustedTemp = lstat("/tmp", &tempInfo) == 0 && S_ISDIR(tempInfo.st_mode) &&
                                 tempInfo.st_uid == 0 && (tempInfo.st_mode & S_ISVTX) != 0;
        const auto parent = trustedTemp ? std::filesystem::path("/tmp") : std::filesystem::current_path();
        const auto pattern = (parent / "virtrust-destination-admission-XXXXXX").string();
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        const char *created = mkdtemp(path.data());
        ASSERT_NE(created, nullptr);
        root_ = created;
        State() = {};
        State().directory = root_ + "/runtime";
    }

    void TearDown() override
    {
        Logger::Instance()->Reset();
        for (const auto &uuid : {"destination-test-1", "destination-test-2", "source-test",
                                 "12345678-1234-1234-1234-123456789001",
                                 "12345678-1234-1234-1234-123456789002",
                                 "12345678-1234-1234-1234-123456789010"}) {
            auto session = SessionManager::GetInstance().GetSession(uuid);
            if (session != nullptr) {
                if (uuid != State().expectedOutstandingUuid) {
                    ADD_FAILURE() << "Session leaked before fixture cleanup: " << uuid;
                }
                session->Cleanup();
            }
        }
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        EXPECT_FALSE(error) << error.message();
        State() = {};
    }

    uint32_t Prepare(const std::string &uuid)
    {
        protos::PrepareMigRequest request;
        request.set_uuid(uuid);
        request.set_domainname("test-domain");
        protos::PrepareMigReply reply;
        const auto status = service_.PrepareMigration(nullptr, &request, &reply);
        EXPECT_TRUE(status.ok());
        return reply.result();
    }

    bool AdvanceToCertVerify(const std::string &uuid)
    {
        State().useRealPrepare = true;
        if (Prepare(uuid) != 0) {
            return false;
        }
        protos::EXchangePkAndReportRequest exchange;
        exchange.set_uuid(uuid);
        exchange.set_domainname("test-domain");
        protos::EXchangePkAndReportReply exchanged;
        if (!service_.ExchangePkAndReport(nullptr, &exchange, &exchanged).ok() || exchanged.result() != 0) {
            return false;
        }
        return true;
    }

    bool AdvanceToTransferring(const std::string &uuid)
    {
        if (!AdvanceToCertVerify(uuid)) {
            return false;
        }
        protos::StartMigRequest start;
        start.set_uuid(uuid);
        start.set_domainname("test-domain");
        protos::StartMigReply started;
        return service_.StartMigration(nullptr, &start, &started).ok() && started.result() == 0;
    }

    bool AdvanceToAwaitingFinish(const std::string &uuid)
    {
        if (!AdvanceToTransferring(uuid)) {
            return false;
        }
        protos::VRsourceInfoRequest request;
        request.set_uuid(uuid);
        request.set_cipherdata("cipher");
        request.mutable_vtpcminfo()->set_name("test-domain");
        request.mutable_vtpcminfo()->set_uuid(uuid);
        protos::VRsourceInfoReply reply;
        return service_.SendVRsourceData(nullptr, &request, &reply).ok() && reply.result() == 0;
    }

    LockOutcome OrdinaryProbe()
    {
        NodeAdmission ordinary;
        const auto result = ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid());
        EXPECT_NE(result, LockOutcome::Error) << ordinary.LastError();
        return result;
    }

    std::string root_;
    MigrationServiceImpl service_;
};

TEST_F(DestinationMigrationAdmissionTest, PrepareHoldsExclusiveAcrossRpcBoundary)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    EXPECT_EQ(Prepare("destination-test-2"), static_cast<uint32_t>(VirtrustRc::BUSY));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-2"), nullptr);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, OrdinaryMutationBlocksPreparation)
{
    NodeAdmission ordinary;
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::BUSY));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    ordinary.Release();
    EXPECT_EQ(Prepare("destination-test-1"), 0U);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, UnsafeRuntimeDirectoryIsErrorNotBusy)
{
    ASSERT_TRUE(std::filesystem::create_directory(State().directory));
    ASSERT_EQ(chmod(State().directory.c_str(), 0755), 0);
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    ASSERT_EQ(chmod(State().directory.c_str(), 0700), 0);
}

TEST_F(DestinationMigrationAdmissionTest, PrepareFailureRemovesSessionAndReleasesAdmission)
{
    State().failPrepare = true;
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, FailureNotificationReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    protos::MigrateResultRequest request;
    request.set_uuid("destination-test-1");
    request.set_result(1);
    protos::MigrateResultReply reply;
    EXPECT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, OutOfOrderRpcAbortsSessionAndReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    protos::StartMigReply reply;
    EXPECT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DirectResponderStepFailureIsTerminalBeforeReturn)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);

    // 直接调用响应方入口，不能依赖外层 RPC 包装延后清理。
    EXPECT_EQ(session->OnStartMigrationRequestReceived(), MigrateSessionRc::ERROR);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(session->OnMigrateRequestReceived(), MigrateSessionRc::ERROR);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DuplicatePrepareTerminatesSession)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    // 已进入 WaitingKey 时重复预检查不是重试成功，不能刷新阶段计时器。
    EXPECT_EQ(session->OnMigrateRequestReceived(), MigrateSessionRc::ERROR);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, FailureMarksTerminalBeforeCleanupBoundary)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    State().probeAtCleanup = true;
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    protos::StartMigReply reply;
    ASSERT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(State().cleanupProbeRan);
    // 清理入口同步模拟另一个 RPC 已持有旧 shared_ptr；失败终态必须先于该入口可见。
    EXPECT_EQ(State().cleanupProbeResult, MigrateSessionRc::ERROR);
    EXPECT_EQ(State().getReportCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DirectResponderExceptionCleansBeforeRethrow)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::DEBUG) {
            throw std::bad_alloc();
        }
    });
    EXPECT_THROW((void)session->OnStartMigrationRequestReceived(), std::bad_alloc);
    Logger::Instance()->Reset();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, NonStandardResponderExceptionCleansBeforeRethrow)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::DEBUG) {
            throw 7;
        }
    });
    EXPECT_THROW((void)session->OnStartMigrationRequestReceived(), int);
    Logger::Instance()->Reset();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ResponderEntryDoesNotTerminateInitiatorSession)
{
    auto &manager = SessionManager::GetInstance();
    auto session = manager.CreateSession(MigrationSession::Role::Initiator, "source-test", "test-domain", "", "", 0);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->OnFinishedRequestReceived(false), MigrateSessionRc::ERROR);
    EXPECT_EQ(manager.GetSession("source-test"), session);
    session->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, StaleResponderEntryCannotAffectReplacementSession)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto stale = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(stale, nullptr);
    stale->Cleanup();
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto replacement = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(replacement, nullptr);
    ASSERT_NE(replacement, stale);

    protos::EXchangePkAndReportRequest request;
    request.set_uuid("destination-test-1");
    protos::EXchangePkAndReportReply reply;
    EXPECT_EQ(stale->OnExchangeKeyRequestReceived(&request, &reply), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().getReportCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), replacement);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    replacement->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, TransferHandlerFailureReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    protos::VRsourceInfoRequest request;
    request.set_uuid("destination-test-1");
    protos::VRsourceInfoReply reply;
    // 准备后的 Init 状态不允许直接导入，业务错误必须立刻结束会话。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangeHandlerFailureReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    protos::EXchangePkAndReportRequest request;
    request.set_uuid("destination-test-1");
    protos::EXchangePkAndReportReply reply;
    // Init 状态收到交换密钥请求时，真实会话处理函数应报错并触发统一清理。
    EXPECT_TRUE(service_.ExchangePkAndReport(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, InvalidImportedDescriptionReleasesAdmission)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(std::string(38, 'x'));
    protos::VRsourceInfoReply reply;
    // 通过真实导入入口，触发 DescriptionFromProto 的超长 UUID 失败。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_NE(reply.result(), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, CipherImportFailureReleasesAdmission)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    State().failCipherImport = true;
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_cipherdata("cipher");
    protos::VRsourceInfoReply reply;
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(State().cipherImportCalls, 1);
    EXPECT_NE(reply.result(), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, CreateVrootFailureReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;
    // mock 已预置该 UUID，CreateVRoot 应返回重复错误并释放准入资格。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_NE(reply.result(), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationFailureStillReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    EXPECT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 1);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ImportCompletionAllowsSuccessNotification)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    State().acceptSuccessNotification = true;
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    EXPECT_EQ(State().cipherImportCalls, 1);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().successNotificationCalls, 1);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, FailureNotificationAfterImportReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(1);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, AwaitingFinishTimeoutReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    State().captureTimers = true;
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    ASSERT_GE(State().timerCallbacks.size(), 4U);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    State().timerCallbacks.back()();
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationBeforeImportIsRejected)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare(uuid), 0U);
    // 预置 UUID 使底层 mock 通知可成功；业务必须先拒绝尚未导入资源的成功通知。
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    EXPECT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationInInitialStateIsRejected)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    // 此夹具的 Prepare 包装仅发布会话，保留 Init，以覆盖最早的非法通知。
    ASSERT_EQ(Prepare(uuid), 0U);
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationBeforeStartIsRejected)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    ASSERT_TRUE(AdvanceToCertVerify(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationDuringTransferIsRejected)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DuplicateTransferAfterImportDoesNotRepeatCipherImport)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    ASSERT_EQ(State().cipherImportCalls, 1);
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;
    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().cipherImportCalls, 1);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, PreparationExceptionReleasesAdmission)
{
    State().throwOnPrepare = true;
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, AdmissionExceptionDoesNotCreateSession)
{
    State().throwOnAcquire = true;
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    State().throwOnAcquire = false;
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, RpcExceptionReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    State().throwOnStart = true;
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    protos::StartMigReply reply;
    grpc::Status status;
    EXPECT_NO_THROW(status = service_.StartMigration(nullptr, &request, &reply));
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DiagnosticExceptionDoesNotRetainAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::DEBUG) {
            throw std::bad_alloc();
        }
    });
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    protos::StartMigReply reply;
    EXPECT_NO_THROW((void)service_.StartMigration(nullptr, &request, &reply));
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TimerCallbackReleasesSessionAndAdmission)
{
    State().useRealPrepare = true;
    State().captureTimers = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(State().timerCallbacks.size(), 1U);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    State().timerCallbacks.front()();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TimerCallbackAndFailureNotificationConvergeToCleanState)
{
    State().useRealPrepare = true;
    State().captureTimers = true;
    for (int attempt = 0; attempt < 20; ++attempt) {
        ASSERT_EQ(Prepare("destination-test-1"), 0U);
        auto session = SessionManager::GetInstance().GetSession("destination-test-1");
        ASSERT_NE(session, nullptr);
        ASSERT_FALSE(State().timerCallbacks.empty());
        auto callback = State().timerCallbacks.back();

        protos::MigrateResultRequest request;
        request.set_uuid("destination-test-1");
        request.set_result(1);
        protos::MigrateResultReply reply;
        // 两个终态入口竞速，验证最终会话已移除且资格可重新取得。
        std::thread timeout([&] { callback(); });
        std::thread notification([&] { (void)service_.NotifyVRMigrateResult(nullptr, &request, &reply); });
        timeout.join();
        notification.join();
        EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
        EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
    }
}

TEST_F(DestinationMigrationAdmissionTest, EarlierTimerGenerationCannotCleanAdvancedState)
{
    State().captureTimers = true;
    ASSERT_TRUE(AdvanceToTransferring("destination-test-1"));
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    ASSERT_GE(State().timerCallbacks.size(), 3U);
    auto staleCallback = State().timerCallbacks[State().timerCallbacks.size() - 2];

    // 阶段推进后，前一阶段的定时器回调不得终结当前会话。
    staleCallback();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), session);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    State().timerCallbacks.back()();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, StaleTimerCallbackCannotCleanReplacementSession)
{
    State().useRealPrepare = true;
    State().captureTimers = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto stale = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(stale, nullptr);
    ASSERT_EQ(State().timerCallbacks.size(), 1U);
    auto staleCallback = State().timerCallbacks.front();
    stale->Cleanup();

    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto replacement = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(replacement, nullptr);
    ASSERT_NE(replacement, stale);
    ASSERT_EQ(State().timerCallbacks.size(), 2U);
    staleCallback();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), replacement);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    State().timerCallbacks.back()();
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, StaleSessionCleanupDoesNotRemoveReplacement)
{
    auto &manager = SessionManager::GetInstance();
    auto stale = manager.CreateSession(MigrationSession::Role::Responder, "destination-test-1", "old", "", "", 0);
    ASSERT_NE(stale, nullptr);
    manager.RemoveSession("destination-test-1");
    NodeAdmission admission;
    ASSERT_EQ(admission.TryAcquire(AdmissionKind::Migration, State().directory, geteuid()), LockOutcome::Acquired);
    auto replacement = manager.CreateSession(MigrationSession::Role::Responder, "destination-test-1", "new", "",
                                             "", 0, std::move(admission));
    ASSERT_NE(replacement, nullptr);

    stale->Cleanup();
    stale->Cleanup();
    EXPECT_EQ(manager.GetSession("destination-test-1"), replacement);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    replacement->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, SourceFailureBeforeAcceptedPrepareDoesNotCancelExistingDestination)
{
    constexpr const char *destinationUuid = "12345678-1234-1234-1234-123456789010";
    NodeAdmission admission;
    ASSERT_EQ(admission.TryAcquire(AdmissionKind::Migration, State().directory, geteuid()), LockOutcome::Acquired);
    auto &manager = SessionManager::GetInstance();
    auto destination = manager.CreateSession(MigrationSession::Role::Responder, destinationUuid, "existing", "", "",
                                             0, std::move(admission));
    ASSERT_NE(destination, nullptr);
    // 单进程测试中源端对象不登记到同一个 manager，保留两端相同的真实 UUID。
    auto source = std::make_shared<MigrationSession>(MigrationSession::Role::Initiator, destinationUuid,
                                                     "new", "", "", 0);
    source->SetRpcClient(std::make_unique<RpcClient>(LinkConfig{}));

    // 真实 Start -> Prepare RPC -> Busy -> OnFail 路径；不能通知并删除已有目的端会话。
    State().useRealClientPrepare = true;
    EXPECT_EQ(source->Start(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().clientPrepareCalls, 1);
    EXPECT_EQ(State().clientPrepareResult, static_cast<uint32_t>(VirtrustRc::BUSY));
    EXPECT_EQ(State().clientNotifyCalls, 0);
    EXPECT_EQ(manager.GetSession(destinationUuid), destination);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    source->Cleanup();
    destination->Cleanup();
}

// 源端资格由 DomainMigrate 的栈对象持有；会话超时不能让仍在执行的请求失去互斥保护。
TEST_F(DestinationMigrationAdmissionTest, SourceTimeoutDuringPrepareKeepsAdmissionUntilRequestReturns)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789002";
    State().captureTimers = true;
    State().expireSourceDuringPrepare = true;
    protos::DomainMigraterRequest request;
    request.set_uuid(uuid);
    request.set_domainname("test-domain-2");
    request.set_localuri("qemu:///system");
    request.set_desturi("qemu+tls://192.168.1.100/system");
    protos::DomainMigraterReply reply;

    EXPECT_TRUE(service_.DomainMigrate(nullptr, &request, &reply).ok());
    EXPECT_EQ(State().clientPrepareCalls, 1);
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

// 已取消的源端回调既不能清理尚待外层收尾的会话，也不能在对象销毁后误删同 UUID 新会话。
TEST_F(DestinationMigrationAdmissionTest, CanceledSourceCallbackCannotRemoveCurrentOrReplacementSession)
{
    State().captureTimers = true;
    auto &manager = SessionManager::GetInstance();
    auto source = manager.CreateSession(MigrationSession::Role::Initiator, "source-test", "source", "", "", 0);
    ASSERT_NE(source, nullptr);
    State().expectedOutstandingUuid = "source-test";
    // 未注入 RPC 客户端：真实 Start 会先计时，再通过 OnFail 取消该代回调。
    EXPECT_EQ(source->Start(), MigrateSessionRc::ERROR);
    ASSERT_EQ(State().timerCallbacks.size(), 1U);
    auto callback = State().timerCallbacks.front();
    callback();
    EXPECT_EQ(manager.GetSession("source-test"), source);

    std::weak_ptr<MigrationSession> previous = source;
    source->Cleanup();
    source.reset();
    EXPECT_TRUE(previous.expired());
    auto replacement = manager.CreateSession(MigrationSession::Role::Initiator, "source-test", "replacement",
                                             "", "", 0);
    ASSERT_NE(replacement, nullptr);
    callback();
    EXPECT_EQ(manager.GetSession("source-test"), replacement);
    replacement->Cleanup();
    State().expectedOutstandingUuid.clear();
}
} // 匿名命名空间
} // 命名空间 virtrust

extern "C" virtrust::LockOutcome RealDestinationAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__real__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedDestinationAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__wrap__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedDestinationAdmission(virtrust::NodeAdmission *self,
    virtrust::AdmissionKind kind, const std::string &directory, uid_t owner)
{
    if (directory != "/run/virtrust") {
        return RealDestinationAdmission(self, kind, directory, owner);
    }
    EXPECT_EQ(kind, virtrust::AdmissionKind::Migration);
    EXPECT_EQ(owner, 0U);
    if (virtrust::State().throwOnAcquire) {
        throw std::bad_alloc();
    }
    return RealDestinationAdmission(self, kind, virtrust::State().directory, geteuid());
}

extern "C" virtrust::MigrateSessionRc RealDestinationPrepare(virtrust::MigrationSession *)
    asm("__real__ZN8virtrust16MigrationSession24OnMigrateRequestReceivedEv");
extern "C" virtrust::MigrateSessionRc WrappedDestinationPrepare(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession24OnMigrateRequestReceivedEv");
extern "C" virtrust::MigrateSessionRc WrappedDestinationPrepare(virtrust::MigrationSession *session)
{
    if (virtrust::State().throwOnPrepare) {
        throw std::runtime_error("Injected preparation failure");
    }
    if (virtrust::State().useRealPrepare) {
        return RealDestinationPrepare(session);
    }
    return virtrust::State().failPrepare ? virtrust::MigrateSessionRc::ERROR : virtrust::MigrateSessionRc::OK;
}

extern "C" virtrust::MigrateSessionRc RealDestinationStart(virtrust::MigrationSession *)
    asm("__real__ZN8virtrust16MigrationSession31OnStartMigrationRequestReceivedEv");
extern "C" virtrust::MigrateSessionRc WrappedDestinationStart(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession31OnStartMigrationRequestReceivedEv");
extern "C" virtrust::MigrateSessionRc WrappedDestinationStart(virtrust::MigrationSession *session)
{
    if (virtrust::State().throwOnStart) {
        throw std::runtime_error("Injected start failure");
    }
    return RealDestinationStart(session);
}

extern "C" void RealDestinationCleanup(virtrust::MigrationSession *)
    asm("__real__ZN8virtrust16MigrationSession7CleanupEv");
extern "C" void WrappedDestinationCleanup(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession7CleanupEv");
extern "C" void WrappedDestinationCleanup(virtrust::MigrationSession *session)
{
    if (virtrust::State().probeAtCleanup) {
        virtrust::State().probeAtCleanup = false;
        virtrust::State().cleanupProbeRan = true;
        virtrust::protos::EXchangePkAndReportRequest request;
        request.set_uuid(session->Id());
        virtrust::protos::EXchangePkAndReportReply reply;
        virtrust::State().cleanupProbeResult = session->OnExchangeKeyRequestReceived(&request, &reply);
    }
    RealDestinationCleanup(session);
}

extern "C" int32_t RealDestinationClientPrepare(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::PrepareMigRequest &, virtrust::protos::PrepareMigReply *)
    asm("__real__ZN8virtrust13RpcClientMock16PrepareMigrationEjRKNS_6protos17PrepareMigRequestEPNS1_15PrepareMigReplyE");
extern "C" int32_t WrappedDestinationClientPrepare(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::PrepareMigRequest &, virtrust::protos::PrepareMigReply *)
    asm("__wrap__ZN8virtrust13RpcClientMock16PrepareMigrationEjRKNS_6protos17PrepareMigRequestEPNS1_15PrepareMigReplyE");
extern "C" int32_t WrappedDestinationClientPrepare(virtrust::RpcClientMock *self, uint32_t timeout,
    const virtrust::protos::PrepareMigRequest &request, virtrust::protos::PrepareMigReply *response)
{
    if (virtrust::State().expireSourceDuringPrepare) {
        ++virtrust::State().clientPrepareCalls;
        EXPECT_EQ(virtrust::State().timerCallbacks.size(), 1U);
        EXPECT_NE(virtrust::SessionManager::GetInstance().GetSession(request.uuid()), nullptr);
        if (!virtrust::State().timerCallbacks.empty()) {
            virtrust::State().timerCallbacks.front()();
        }
        EXPECT_EQ(virtrust::SessionManager::GetInstance().GetSession(request.uuid()), nullptr);
        virtrust::NodeAdmission ordinary;
        EXPECT_EQ(ordinary.TryAcquire(virtrust::AdmissionKind::OrdinaryMutation, virtrust::State().directory,
                                      geteuid()), virtrust::LockOutcome::Busy);
        // 注入 Prepare 失败，让真实 Start/DomainMigrate 收尾；不模拟完整迁移或声称超时可取消 RPC。
        response->set_result(static_cast<uint32_t>(virtrust::VirtrustRc::ERROR));
        return 0;
    }
    if (!virtrust::State().useRealClientPrepare) {
        return RealDestinationClientPrepare(self, timeout, request, response);
    }
    ++virtrust::State().clientPrepareCalls;
    virtrust::MigrationServiceImpl service;
    const auto status = service.PrepareMigration(nullptr, &request, response);
    if (!status.ok()) {
        return -1;
    }
    virtrust::State().clientPrepareResult = response->result();
    return 0;
}

extern "C" int32_t RealDestinationClientNotify(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::MigrateResultRequest &, virtrust::protos::MigrateResultReply *)
    asm("__real__ZN8virtrust13RpcClientMock21NotifyVRMigrateResultEjRKNS_6protos20MigrateResultRequestEPNS1_18MigrateResultReplyE");
extern "C" int32_t WrappedDestinationClientNotify(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::MigrateResultRequest &, virtrust::protos::MigrateResultReply *)
    asm("__wrap__ZN8virtrust13RpcClientMock21NotifyVRMigrateResultEjRKNS_6protos20MigrateResultRequestEPNS1_18MigrateResultReplyE");
extern "C" int32_t WrappedDestinationClientNotify(virtrust::RpcClientMock *self, uint32_t timeout,
    const virtrust::protos::MigrateResultRequest &request, virtrust::protos::MigrateResultReply *response)
{
    if (!virtrust::State().useRealClientPrepare) {
        return RealDestinationClientNotify(self, timeout, request, response);
    }
    ++virtrust::State().clientNotifyCalls;
    virtrust::MigrationServiceImpl service;
    return service.NotifyVRMigrateResult(nullptr, &request, response).ok() ? 0 : -1;
}

// AsyncTimer::Start 在头文件内联定义；本测试用强符号覆盖弱定义，捕获真实会话创建的回调。
extern "C" void CaptureDestinationTimerStart(virtrust::AsyncTimer *, std::chrono::microseconds,
    std::function<void()>)
    asm("_ZN8virtrust10AsyncTimer5StartENSt6chrono8durationIlSt5ratioILl1ELl1000000EEEESt8functionIFvvEE");
extern "C" void CaptureDestinationTimerStart(virtrust::AsyncTimer *, std::chrono::microseconds,
    std::function<void()> callback)
{
    if (virtrust::State().captureTimers) {
        virtrust::State().timerCallbacks.push_back(std::move(callback));
    }
}

extern "C" int RealDestinationCipherImport(char *, char *, char *, int)
    asm("__real_MigrationImportVrootCipher");
extern "C" int WrappedDestinationCipherImport(char *, char *, char *, int)
    asm("__wrap_MigrationImportVrootCipher");
extern "C" int WrappedDestinationCipherImport(char *physicalUuid, char *virtualUuid, char *cipher, int length)
{
    ++virtrust::State().cipherImportCalls;
    if (virtrust::State().failCipherImport) {
        return -1;
    }
    return RealDestinationCipherImport(physicalUuid, virtualUuid, cipher, length);
}

extern "C" int RealDestinationMigrationNotify(char *, int) asm("__real_MigrationNotify");
extern "C" int WrappedDestinationMigrationNotify(char *, int) asm("__wrap_MigrationNotify");
extern "C" int WrappedDestinationMigrationNotify(char *uuid, int status)
{
    if (status == 0) {
        ++virtrust::State().successNotificationCalls;
        if (virtrust::State().acceptSuccessNotification) {
            return 0;
        }
    }
    return RealDestinationMigrationNotify(uuid, status);
}

extern "C" int RealDestinationGetReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__real_GetReport");
extern "C" int WrappedDestinationGetReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__wrap_GetReport");
extern "C" int WrappedDestinationGetReport(char *physicalUuid, char *virtualUuid,
    trust_report_new *hostReport, trust_report_new *vmReport)
{
    ++virtrust::State().getReportCalls;
    const int result = RealDestinationGetReport(physicalUuid, virtualUuid, hostReport, vmReport);
    if (result == 0 && hostReport != nullptr && vmReport != nullptr) {
        // 现有 mock 的 GetReport 返回成功但不写输出；测试在序列化前补齐确定性数据。
        *hostReport = {};
        *vmReport = {};
    }
    return result;
}
