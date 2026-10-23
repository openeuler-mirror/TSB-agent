/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "virtrust/api/defines.h"
#include "virtrust/base/logger.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/migration_service_impl.h"
#include "virtrust/link/migration_result.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
namespace {
// 测试请求按 UUID 固定尝试身份，使不同阶段同属一次迁移、不同虚机不发生缓存键冲突。
std::string TestAttemptId(const std::string &uuid)
{
    constexpr char digits[] = "0123456789abcdef";
    const auto value = std::hash<std::string>{}(uuid);
    std::string id(32, '0');
    for (size_t index = 0; index < 16; ++index) {
        id[index] = digits[(value >> (index * 4 % (sizeof(size_t) * 8))) & 0x0f];
        id[index + 16] = id[index];
    }
    return id;
}

struct DestinationTestState {
    std::string directory;
    std::string expectedOutstandingUuid;
    bool failPrepare = false;
    bool useRealPrepare = false;
    bool throwOnPrepare = false;
    bool throwOnStart = false;
    bool throwOnDiagnostic = false;
    bool throwOnDiagnosticSerialization = false;
    bool throwOnAcquire = false;
    bool useRealClientPrepare = false;
    bool failSourcePrepareTransport = false;
    bool failSourceExchangeTransport = false;
    bool failSourceExchangeBusiness = false;
    bool replaceSourceExchangeReplyUuid = false;
    bool wrongReplyDelivered = false;
    int postWrongReplyCertificateCalls = 0;
    int postWrongReplyReportChecks = 0;
    int postWrongReplyKeyImports = 0;
    bool failSourceStartTransport = false;
    // 在源端同步 Prepare 调用尚未返回时，确定性触发会话阶段超时。
    bool expireSourceDuringPrepare = false;
    bool acceptPrepareAfterSourceTimeout = false;
    bool rejectSourceFinish = false;
    bool failSourceFinishTransport = false;
    bool failSourceSuccessNotify = false;
    bool failSourceCipherFetch = false;
    bool injectSourceCipherLength = false;
    int sourceCipherLength = 0;
    bool failSourceDescriptionFetch = false;
    int forcedRootCount = -1;
    bool sourceTimeoutObservedInLibvirt = false;
    bool captureTimers = false;
    bool failCipherImport = false;
    bool failGetCert = false;
    // INT_MIN 表示不覆盖底层返回的长度。
    int certLengthOverride = INT_MIN;
    int publicKeyLengthOverride = INT_MIN;
    void *trackedCert = nullptr;
    void *trackedPublicKey = nullptr;
    int certFreeCalls = 0;
    int publicKeyFreeCalls = 0;
    bool failGetReport = false;
    bool failPeerCertificate = false;
    bool failPeerReport = false;
    bool failKeyExport = false;
    bool failSourceKeyImport = false;
    bool sourceDuplicateTransfer = false;
    bool sourceTransferTransportFailure = false;
    bool failSourceFailureNotify = false;
    bool failSourceFailurePeerNotify = false;
    bool acceptSuccessNotification = false;
    bool probeAtCleanup = false;
    bool cleanupProbeRan = false;
    int cipherImportCalls = 0;
    int createVRootCalls = 0;
    int getReportCalls = 0;
    int successNotificationCalls = 0;
    MigrateSessionRc cleanupProbeResult = MigrateSessionRc::OK;
    int clientPrepareCalls = 0;
    int clientNotifyCalls = 0;
    int sourceDataCalls = 0;
    uint32_t clientPrepareResult = 0;
    int removeCalls = 0;
    int undefineCalls = 0;
    int sourceMigrateCalls = 0;
    int removeFailuresRemaining = 0;
    int undefineFailuresRemaining = 0;
    std::vector<std::string> sourceCompletionOrder;
    std::vector<std::string> sourceAttemptIds;
    MigrationResult lastSourceDiagnostic;
    std::vector<std::function<void()>> timerCallbacks;
};

DestinationTestState &State()
{
    static DestinationTestState state;
    return state;
}

virDomainPtr ExpireSourceInsideLibvirt(virDomainPtr, virConnectPtr, virTypedParameterPtr,
                                       unsigned int, unsigned int)
{
    auto source = SessionManager::GetInstance().GetSession("12345678-1234-1234-1234-123456789002");
    EXPECT_NE(source, nullptr);
    if (source) {
        source->OnTimeout(MigrationSession::State::Transferring);
        State().sourceTimeoutObservedInLibvirt =
            SessionManager::GetInstance().GetSession(source->Id()) == source;
    }
    return reinterpret_cast<virDomainPtr>(0x98765432);
}

int RecordSourceUndefine(virDomainPtr domain, unsigned int flags)
{
    EXPECT_NE(domain, nullptr);
    EXPECT_EQ(flags, DOMAIN_UNDEFINE_NVRAM);
    auto &state = State();
    state.sourceCompletionOrder.push_back("source-undefine");
    ++state.undefineCalls;
    if (state.undefineFailuresRemaining > 0) {
        --state.undefineFailuresRemaining;
        return -1;
    }
    return 0;
}

int ReturnDifferentSourceUuid(virDomainPtr, char *uuid)
{
    constexpr char other[] = "12345678-1234-1234-1234-123456789001";
    std::memcpy(uuid, other, sizeof(other));
    return 0;
}

int FailSourceUuidLookup(virDomainPtr, char *)
{
    return -1;
}

virDomainPtr CountSourceMigration(virDomainPtr, virConnectPtr, virTypedParameterPtr,
                                  unsigned int, unsigned int)
{
    ++State().sourceMigrateCalls;
    return reinterpret_cast<virDomainPtr>(0x98765432);
}

// 让源域身份与会话不一致，并观察是否越过身份边界调用真正的迁移入口。
class ScopedSourceIdentityProbe {
public:
    explicit ScopedSourceIdentityProbe(int (*lookup)(virDomainPtr, char *))
        : uuidLookup_(Libvirt::GetInstance().virDomainGetUUIDString), originalUuid_(uuidLookup_),
          migration_(Libvirt::GetInstance().virDomainMigrate3), originalMigration_(migration_)
    {
        uuidLookup_ = UuidLookup("virDomainGetUUIDString", lookup);
        migration_ = Migration("virDomainMigrate3", CountSourceMigration);
    }

    ~ScopedSourceIdentityProbe()
    {
        uuidLookup_ = originalUuid_;
        migration_ = originalMigration_;
    }
    ScopedSourceIdentityProbe(const ScopedSourceIdentityProbe &) = delete;
    ScopedSourceIdentityProbe &operator=(const ScopedSourceIdentityProbe &) = delete;

private:
    using UuidLookup = std::remove_reference_t<decltype(Libvirt::GetInstance().virDomainGetUUIDString)>;
    using Migration = std::remove_reference_t<decltype(Libvirt::GetInstance().virDomainMigrate3)>;
    UuidLookup &uuidLookup_;
    UuidLookup originalUuid_;
    Migration &migration_;
    Migration originalMigration_;
};

// 只观察是否越过密文校验进入 libvirt，不改变源域 UUID。
class ScopedSourceMigrationCounter {
public:
    ScopedSourceMigrationCounter()
        : migration_(Libvirt::GetInstance().virDomainMigrate3), original_(migration_)
    {
        migration_ = Migration("virDomainMigrate3", CountSourceMigration);
    }
    ~ScopedSourceMigrationCounter() { migration_ = original_; }
    ScopedSourceMigrationCounter(const ScopedSourceMigrationCounter &) = delete;
    ScopedSourceMigrationCounter &operator=(const ScopedSourceMigrationCounter &) = delete;

private:
    using Migration = std::remove_reference_t<decltype(Libvirt::GetInstance().virDomainMigrate3)>;
    Migration &migration_;
    Migration original_;
};

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

    uint32_t Prepare(const std::string &uuid, const std::string &attemptId = {})
    {
        protos::PrepareMigRequest request;
        request.set_uuid(uuid);
        request.set_attempt_id(attemptId.empty() ? TestAttemptId(uuid) : attemptId);
        request.set_domainname("test-domain");
        protos::PrepareMigReply reply;
        const auto status = service_.PrepareMigration(nullptr, &request, &reply);
        EXPECT_TRUE(status.ok());
        return reply.result();
    }

    protos::EXchangePkAndReportReply ExchangeAfterPrepare(const std::string &uuid)
    {
        State().useRealPrepare = true;
        EXPECT_EQ(Prepare(uuid), 0U);
        protos::EXchangePkAndReportRequest request;
        request.set_uuid(uuid);
        request.set_attempt_id(TestAttemptId(request.uuid()));
        request.set_domainname("test-domain");
        protos::EXchangePkAndReportReply reply;
        EXPECT_TRUE(service_.ExchangePkAndReport(nullptr, &request, &reply).ok());
        return reply;
    }

    bool AdvanceToCertVerify(const std::string &uuid)
    {
        State().useRealPrepare = true;
        if (Prepare(uuid) != 0) {
            return false;
        }
        protos::EXchangePkAndReportRequest exchange;
        exchange.set_uuid(uuid);
        exchange.set_attempt_id(TestAttemptId(exchange.uuid()));
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
        start.set_attempt_id(TestAttemptId(start.uuid()));
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
        request.set_attempt_id(TestAttemptId(request.uuid()));
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

    MigrateSessionRc RunMockSource(unsigned int flags = 0)
    {
        State().captureTimers = true;
        constexpr const char *uuid = "12345678-1234-1234-1234-123456789002";
        auto session = SessionManager::GetInstance().CreateSession(
            MigrationSession::Role::Initiator, uuid, "test-domain-2", "qemu+tls://192.168.1.100/system",
            "qemu:///system", flags);
        EXPECT_NE(session, nullptr);
        if (!session) {
            return MigrateSessionRc::ERROR;
        }
        session->SetRpcClient(std::make_unique<RpcClient>(LinkConfig{}));
        MigrateSessionRc result;
        try {
            result = session->Start();
        } catch (...) {
            session->Cleanup();
            throw;
        }
        State().lastSourceDiagnostic = session->Diagnostic();
        session->Cleanup();
        return result;
    }

    MigrateSessionRc RunSourceWithObservedUndefine()
    {
        auto &undefine = Libvirt::GetInstance().virDomainUndefineFlags;
        struct RestoreUndefine {
            decltype(undefine) target;
            std::remove_reference_t<decltype(undefine)> original;
            ~RestoreUndefine() { target = original; }
        } restore{undefine, undefine};
        undefine = decltype(restore.original)("virDomainUndefineFlags", RecordSourceUndefine);
        return RunMockSource(MIGRATE_UNDEFINE_SOURCE);
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

TEST_F(DestinationMigrationAdmissionTest, RepeatedPrepareReplaysReplyWithoutRefreshingSession)
{
    State().useRealPrepare = true;
    State().captureTimers = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(State().timerCallbacks.size(), 1U);
    EXPECT_EQ(Prepare("destination-test-1"), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), session);
    EXPECT_EQ(State().timerCallbacks.size(), 1U);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, OldPrepareReplyIsNotReplayedIntoReplacementSession)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto first = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(first, nullptr);
    first->Cleanup();
    ASSERT_EQ(Prepare("destination-test-1", TestAttemptId("replacement-attempt")), 0U);
    auto replacement = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(replacement, nullptr);

    protos::PrepareMigRequest oldRequest;
    oldRequest.set_uuid("destination-test-1");
    oldRequest.set_attempt_id(TestAttemptId(oldRequest.uuid()));
    oldRequest.set_domainname("test-domain");
    protos::PrepareMigReply reply;
    EXPECT_EQ(service_.PrepareMigration(nullptr, &oldRequest, &reply).error_code(),
              grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), replacement);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, ChangedPreparePayloadAndMissingAttemptAreRejected)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    protos::PrepareMigRequest changed;
    changed.set_uuid("destination-test-1");
    changed.set_attempt_id(TestAttemptId(changed.uuid()));
    changed.set_domainname("changed-name");
    protos::PrepareMigReply reply;
    EXPECT_EQ(service_.PrepareMigration(nullptr, &changed, &reply).error_code(),
              grpc::StatusCode::FAILED_PRECONDITION);
    changed.clear_attempt_id();
    EXPECT_EQ(service_.PrepareMigration(nullptr, &changed, &reply).error_code(),
              grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), session);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, StaleAttemptCannotEnterCurrentResponderSession)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    auto session = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(session, nullptr);
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId("old-attempt"));
    protos::StartMigReply reply;
    ASSERT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().getReportCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), session);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, RepeatedExchangeReplaysWithoutFetchingReportsAgain)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    const auto first = ExchangeAfterPrepare(uuid);
    ASSERT_EQ(first.result(), static_cast<uint32_t>(VirtrustRc::OK));
    const auto reportCalls = State().getReportCalls;
    auto session = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(session, nullptr);
    protos::EXchangePkAndReportRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(uuid));
    request.set_domainname("test-domain");
    protos::EXchangePkAndReportReply repeated;
    ASSERT_TRUE(service_.ExchangePkAndReport(nullptr, &request, &repeated).ok());
    EXPECT_EQ(repeated.SerializeAsString(), first.SerializeAsString());
    EXPECT_EQ(State().getReportCalls, reportCalls);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), session);
    State().expectedOutstandingUuid = uuid;
}

TEST_F(DestinationMigrationAdmissionTest, RepeatedStartReplaysWithoutRefreshingTimer)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    State().captureTimers = true;
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    const auto timerCount = State().timerCallbacks.size();
    auto session = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(session, nullptr);
    protos::StartMigRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(uuid));
    request.set_domainname("test-domain");
    protos::StartMigReply repeated;
    ASSERT_TRUE(service_.StartMigration(nullptr, &request, &repeated).ok());
    EXPECT_EQ(repeated.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().timerCallbacks.size(), timerCount);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), session);
    State().expectedOutstandingUuid = uuid;
}

TEST_F(DestinationMigrationAdmissionTest, OrdinaryMutationBlocksPreparation)
{
    NodeAdmission ordinary;
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
    EXPECT_EQ(Prepare("destination-test-1"), static_cast<uint32_t>(VirtrustRc::BUSY));
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    ordinary.Release();
    EXPECT_EQ(Prepare("destination-test-1", TestAttemptId("second-attempt")), 0U);
    State().expectedOutstandingUuid = "destination-test-1";
}

TEST_F(DestinationMigrationAdmissionTest, PrepareBusyReportsNoEffectDiagnostic)
{
    NodeAdmission ordinary;
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
    protos::PrepareMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::PrepareMigReply reply;

    ASSERT_TRUE(service_.PrepareMigration(nullptr, &request, &reply).ok());
    ASSERT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::BUSY));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::BUSY);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::AcquireAdmission);
    EXPECT_FALSE(diagnostic.manualCheckRequired);
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

TEST_F(DestinationMigrationAdmissionTest, PreparePrecheckFailureReportsNoEffectDiagnostic)
{
    State().failPrepare = true;
    protos::PrepareMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::PrepareMigReply reply;

    ASSERT_TRUE(service_.PrepareMigration(nullptr, &request, &reply).ok());
    ASSERT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_FALSE(diagnostic.manualCheckRequired);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
}

TEST_F(DestinationMigrationAdmissionTest, PrepareTsbQueryFailureKeepsOriginAndRawCode)
{
    State().useRealPrepare = true;
    State().failSourceDescriptionFetch = true;
    protos::PrepareMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::PrepareMigReply reply;
    ASSERT_TRUE(service_.PrepareMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetDescription);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, PrepareCapacityLimitRemainsValidation)
{
    State().useRealPrepare = true;
    State().forcedRootCount = 32;
    protos::PrepareMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::PrepareMigReply reply;
    ASSERT_TRUE(service_.PrepareMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Validation);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
}

TEST_F(DestinationMigrationAdmissionTest, ZeroLengthCertificateIsRejectedAndBuffersReleased)
{
    State().certLengthOverride = 0;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCertificate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(State().certFreeCalls, 1);
    EXPECT_EQ(State().publicKeyFreeCalls, 1);
    EXPECT_EQ(State().getReportCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, NegativePublicKeyLengthIsRejectedAndBuffersReleased)
{
    State().publicKeyLengthOverride = -1;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCertificate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(State().certFreeCalls, 1);
    EXPECT_EQ(State().publicKeyFreeCalls, 1);
    EXPECT_EQ(State().getReportCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, FailureNotificationReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    protos::MigrateResultRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::StartMigReply reply;
    EXPECT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Start);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DiagnosticSnapshotFailureCannotReturnDefaultSuccess)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    State().throwOnDiagnostic = true;
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::StartMigReply reply;
    EXPECT_NO_THROW({ EXPECT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok()); });
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_FALSE(reply.has_diagnostic());
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DiagnosticSerializationFailureCannotReturnDefaultSuccess)
{
    State().useRealPrepare = true;
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    State().throwOnDiagnosticSerialization = true;
    protos::StartMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::StartMigReply reply;
    EXPECT_NO_THROW({ EXPECT_TRUE(service_.StartMigration(nullptr, &request, &reply).ok()); });
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_FALSE(reply.has_diagnostic());
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    ASSERT_EQ(Prepare("destination-test-1", TestAttemptId("replacement-attempt")), 0U);
    auto replacement = SessionManager::GetInstance().GetSession("destination-test-1");
    ASSERT_NE(replacement, nullptr);
    ASSERT_NE(replacement, stale);

    protos::EXchangePkAndReportRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::VRsourceInfoReply reply;
    // 准备后的 Init 状态不允许直接导入，业务错误必须立刻结束会话。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangeHandlerFailureReleasesAdmission)
{
    ASSERT_EQ(Prepare("destination-test-1"), 0U);
    protos::EXchangePkAndReportRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::EXchangePkAndReportReply reply;
    // Init 状态收到交换密钥请求时，真实会话处理函数应报错并触发统一清理。
    EXPECT_TRUE(service_.ExchangePkAndReport(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangeGetCertFailureReturnsTsbDiagnostic)
{
    State().failGetCert = true;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCertificate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -71);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangeGetReportFailureReturnsTsbDiagnostic)
{
    State().failGetReport = true;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetReport);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -72);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangePeerCertificateFailureReturnsTsbDiagnostic)
{
    State().failPeerCertificate = true;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::VerifyCertificate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -73);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangePeerReportFailureReturnsTsbDiagnostic)
{
    State().failPeerReport = true;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::VerifyReport);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -74);
}

TEST_F(DestinationMigrationAdmissionTest, ExchangeKeyExportFailureReturnsTsbDiagnostic)
{
    State().failKeyExport = true;
    const auto reply = ExchangeAfterPrepare("destination-test-1");
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::ExportKey);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -75);
}

TEST_F(DestinationMigrationAdmissionTest, InvalidImportedDescriptionReleasesAdmission)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(std::string(38, 'x'));
    protos::VRsourceInfoReply reply;
    // 通过真实导入入口，触发 DescriptionFromProto 的超长 UUID 失败。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(State().cipherImportCalls, 0);
    EXPECT_EQ(State().createVRootCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TransferRejectsMismatchedDescriptionUuidBeforeTsbCalls)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid("destination-test-2");
    protos::VRsourceInfoReply reply;

    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(State().cipherImportCalls, 0);
    EXPECT_EQ(State().createVRootCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TransferRejectsMismatchedDescriptionNameBeforeTsbCalls)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("other-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;

    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(State().cipherImportCalls, 0);
    EXPECT_EQ(State().createVRootCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TransferRejectsMismatchedRequestUuidBeforeTsbCalls)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    auto session = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(session, nullptr);
    protos::VRsourceInfoRequest request;
    request.set_uuid("destination-test-2");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);

    EXPECT_EQ(session->OnTransferDataRequestReceived(&request), MigrateSessionRc::ERROR);
    const auto diagnostic = session->Diagnostic();
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(State().cipherImportCalls, 0);
    EXPECT_EQ(State().createVRootCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, TransferAcceptsSourceUuidWithTerminalNull)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    std::string descriptionUuid(uuid);
    descriptionUuid.push_back('\0');
    request.mutable_vtpcminfo()->set_uuid(descriptionUuid);
    protos::VRsourceInfoReply reply;

    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().cipherImportCalls, 1);
    EXPECT_EQ(State().createVRootCalls, 1);
    auto session = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    session->Cleanup();
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, CipherImportFailureReleasesAdmission)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    State().failCipherImport = true;
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(State().cipherImportCalls, 1);
    EXPECT_NE(reply.result(), 0U);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, CipherImportFailureReturnsTsbDiagnostic)
{
    constexpr const char *uuid = "destination-test-1";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    State().failCipherImport = true;
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;

    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    ASSERT_NE(reply.result(), 0U);
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::ImportCipher);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -1);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
}

TEST_F(DestinationMigrationAdmissionTest, CreateVrootFailureReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789001";
    ASSERT_TRUE(AdvanceToTransferring(uuid));
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;
    // mock 已预置该 UUID，CreateVRoot 返回非零错误并释放准入资格；mock 只给出 -1。
    EXPECT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CreateVRoot);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -1);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SuccessNotificationFailureStillReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_result(0);
    protos::MigrateResultReply reply;
    EXPECT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DestinationCommit);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyTsb);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -1);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().successNotificationCalls, 1);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, FinalReplyReplaysAfterSessionCleanup)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    State().acceptSuccessNotification = true;
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(uuid));
    request.set_result(0);
    protos::MigrateResultReply first;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &first).ok());
    ASSERT_EQ(first.result(), static_cast<uint32_t>(VirtrustRc::OK));
    ASSERT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    protos::MigrateResultReply repeated;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &repeated).ok());
    EXPECT_EQ(repeated.SerializeAsString(), first.SerializeAsString());
    EXPECT_EQ(State().successNotificationCalls, 1);
}

TEST_F(DestinationMigrationAdmissionTest, OldFinalReplyIsNotReplayedIntoReplacementSession)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    State().acceptSuccessNotification = true;
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(uuid));
    request.set_result(0);
    protos::MigrateResultReply first;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &first).ok());
    ASSERT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);

    // 此处只测试身份隔离，新会话预检查由其他用例覆盖。
    State().useRealPrepare = false;
    ASSERT_EQ(Prepare(uuid, TestAttemptId("replacement-after-finish")), 0U);
    auto replacement = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(replacement, nullptr);
    protos::MigrateResultReply repeated;
    EXPECT_EQ(service_.NotifyVRMigrateResult(nullptr, &request, &repeated).error_code(),
              grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), replacement);
    EXPECT_EQ(State().successNotificationCalls, 1);
    State().expectedOutstandingUuid = uuid;
}

TEST_F(DestinationMigrationAdmissionTest, FailureNotificationAfterImportReleasesAdmission)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    protos::MigrateResultRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_result(0);
    protos::MigrateResultReply reply;
    EXPECT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DestinationCommit);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_result(0);
    protos::MigrateResultReply reply;
    ASSERT_TRUE(service_.NotifyVRMigrateResult(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().successNotificationCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, DuplicateTransferAfterImportReplaysWithoutRepeatingCipherImport)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789010";
    ASSERT_TRUE(AdvanceToAwaitingFinish(uuid));
    ASSERT_EQ(State().cipherImportCalls, 1);
    protos::VRsourceInfoRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_cipherdata("cipher");
    request.mutable_vtpcminfo()->set_name("test-domain");
    request.mutable_vtpcminfo()->set_uuid(uuid);
    protos::VRsourceInfoReply reply;
    ASSERT_TRUE(service_.SendVRsourceData(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().cipherImportCalls, 1);
    auto session = SessionManager::GetInstance().GetSession(uuid);
    ASSERT_NE(session, nullptr);
    session->Cleanup();
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, PreparationExceptionReleasesAdmission)
{
    State().throwOnPrepare = true;
    protos::PrepareMigRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::PrepareMigReply reply;
    ASSERT_TRUE(service_.PrepareMigration(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
    protos::StartMigReply reply;
    grpc::Status status;
    EXPECT_NO_THROW(status = service_.StartMigration(nullptr, &request, &reply));
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Start);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_EQ(SessionManager::GetInstance().GetSession("destination-test-1"), nullptr);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, MissingExchangeSessionReturnsUnknownDiagnostic)
{
    protos::EXchangePkAndReportRequest request;
    request.set_uuid("destination-test-1");
    request.set_attempt_id(TestAttemptId(request.uuid()));
    request.set_domainname("test-domain");
    protos::EXchangePkAndReportReply reply;
    ASSERT_TRUE(service_.ExchangePkAndReport(nullptr, &request, &reply).ok());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    const auto diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
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
    request.set_attempt_id(TestAttemptId(request.uuid()));
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
        const auto attemptId = TestAttemptId("destination-test-1-" + std::to_string(attempt));
        ASSERT_EQ(Prepare("destination-test-1", attemptId), 0U);
        auto session = SessionManager::GetInstance().GetSession("destination-test-1");
        ASSERT_NE(session, nullptr);
        ASSERT_FALSE(State().timerCallbacks.empty());
        auto callback = State().timerCallbacks.back();

        protos::MigrateResultRequest request;
        request.set_uuid("destination-test-1");
        request.set_attempt_id(attemptId);
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

    ASSERT_EQ(Prepare("destination-test-1", TestAttemptId("timer-replacement")), 0U);
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
    const auto diagnostic = source->Diagnostic();
    EXPECT_EQ(diagnostic.rc, VirtrustRc::BUSY);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::AcquireAdmission);
    EXPECT_FALSE(diagnostic.manualCheckRequired);
    EXPECT_EQ(manager.GetSession(destinationUuid), destination);
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Busy);
    source->Cleanup();
    destination->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, PrepareTransportFailureDoesNotTrustDefaultReply)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789002";
    State().failSourcePrepareTransport = true;
    auto source = std::make_shared<MigrationSession>(MigrationSession::Role::Initiator, uuid,
        "test-domain-2", "qemu+tls://192.168.1.100/system", "qemu:///system", 0);
    source->SetRpcClient(std::make_unique<RpcClient>(LinkConfig{}));
    EXPECT_EQ(source->Start(), MigrateSessionRc::ERROR);
    const auto diagnostic = source->Diagnostic();
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
    EXPECT_EQ(State().clientNotifyCalls, 0);
    source->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, SourceMissingRpcClientStopsBeforeEffect)
{
    auto source = std::make_shared<MigrationSession>(MigrationSession::Role::Initiator,
        "12345678-1234-1234-1234-123456789002", "test-domain-2");
    EXPECT_EQ(source->Start(), MigrateSessionRc::ERROR);
    const auto diagnostic = source->Diagnostic();
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::FailedBeforeEffect);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Prepare);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::Validate);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_FALSE(diagnostic.manualCheckRequired);
    source->Cleanup();
}

TEST_F(DestinationMigrationAdmissionTest, SourceExchangeTransportFailureDoesNotTrustDefaultReply)
{
    State().failSourceExchangeTransport = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
}

TEST_F(DestinationMigrationAdmissionTest, SourceExchangeBusinessFailurePreservesDestinationCause)
{
    State().failSourceExchangeBusiness = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetReport);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
}

TEST_F(DestinationMigrationAdmissionTest, SourceRejectsExchangeReplyWithDifferentUuidBeforeCertificateCheck)
{
    State().replaceSourceExchangeReplyUuid = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_TRUE(State().wrongReplyDelivered);
    EXPECT_EQ(State().postWrongReplyCertificateCalls, 0);
    EXPECT_EQ(State().postWrongReplyReportChecks, 0);
    EXPECT_EQ(State().postWrongReplyKeyImports, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Validation);
}

TEST_F(DestinationMigrationAdmissionTest, SourceStartTransportFailureDoesNotTrustDefaultReply)
{
    State().failSourceStartTransport = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::Start);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
}

// 手动持有真实准入锁来模拟外层请求；本用例验证会话未被超时回调提前移除，不覆盖 DomainMigrate 入口。
TEST_F(DestinationMigrationAdmissionTest, SourceTimeoutDuringPrepareKeepsSessionWhileExternalAdmissionHeld)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789002";
    State().captureTimers = true;
    State().expireSourceDuringPrepare = true;
    NodeAdmission admission;
    ASSERT_EQ(admission.TryAcquire(AdmissionKind::Migration, State().directory, geteuid()), LockOutcome::Acquired);
    auto session = SessionManager::GetInstance().CreateSession(MigrationSession::Role::Initiator, uuid,
                                                               "test-domain-2", "", "", 0);
    ASSERT_NE(session, nullptr);
    session->SetRpcClient(std::make_unique<RpcClient>(LinkConfig{}));
    EXPECT_EQ(session->Start(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().clientPrepareCalls, 1);
    session->Cleanup();
    session.reset();
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    admission.Release();
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

// Prepare 超时后若模拟返回成功，验证源端会继续执行；后续 RPC 仍由 mock 提供结果。
TEST_F(DestinationMigrationAdmissionTest, SourceTimeoutAfterAcceptedPrepareCanStillSucceed)
{
    constexpr const char *uuid = "12345678-1234-1234-1234-123456789002";
    State().captureTimers = true;
    State().expireSourceDuringPrepare = true;
    State().acceptPrepareAfterSourceTimeout = true;
    NodeAdmission admission;
    ASSERT_EQ(admission.TryAcquire(AdmissionKind::Migration, State().directory, geteuid()), LockOutcome::Acquired);
    auto session = SessionManager::GetInstance().CreateSession(MigrationSession::Role::Initiator, uuid,
                                                               "test-domain-2", "qemu+tls://192.168.1.100/system",
                                                               "qemu:///system", 0);
    ASSERT_NE(session, nullptr);
    session->SetRpcClient(std::make_unique<RpcClient>(LinkConfig{}));
    EXPECT_EQ(session->Start(), MigrateSessionRc::OK);
    EXPECT_EQ(State().clientPrepareCalls, 1);
    EXPECT_GT(State().getReportCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    session->Cleanup();
    session.reset();
    EXPECT_EQ(SessionManager::GetInstance().GetSession(uuid), nullptr);
    admission.Release();
    EXPECT_EQ(OrdinaryProbe(), LockOutcome::Acquired);
}

TEST_F(DestinationMigrationAdmissionTest, SourceSuccessRequiresDestinationFinalAcknowledgment)
{
    State().rejectSourceFinish = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().successNotificationCalls, 1);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DestinationCommit);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Destination);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyTsb);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
}

TEST_F(DestinationMigrationAdmissionTest, SourceLibvirtTransferFailureRecordsStage)
{
    auto &migration = Libvirt::GetInstance().virDomainMigrate3;
    struct RestoreMigration {
        decltype(migration) target;
        std::remove_reference_t<decltype(migration)> original;
        ~RestoreMigration() { target = original; }
    } restore{migration, migration};
    migration = decltype(restore.original)("virDomainMigrate3",
        +[](virDomainPtr, virConnectPtr, virTypedParameterPtr, unsigned int, unsigned int) -> virDomainPtr {
            return nullptr;
        });

    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::LibvirtTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::MigrateLibvirt);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Libvirt);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
}

TEST_F(DestinationMigrationAdmissionTest, SourceRejectsReplacedDomainBeforeLibvirtMigration)
{
    ScopedSourceIdentityProbe probe(ReturnDifferentSourceUuid);
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().sourceMigrateCalls, 0);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::LibvirtTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Validation);
}

TEST_F(DestinationMigrationAdmissionTest, SourceRejectsUnreadableDomainUuidBeforeLibvirtMigration)
{
    ScopedSourceIdentityProbe probe(FailSourceUuidLookup);
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().sourceMigrateCalls, 0);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::LibvirtTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::CheckIdentity);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Libvirt);
}

// 模拟目的端成功回复；验证源端只在收到回复后，依次删除可信资源和定义。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRunsAfterSuccessReplyAndDeletesVrootFirst)
{
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::OK);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Success);
    EXPECT_FALSE(diagnostic.hasPrimaryError);
    EXPECT_FALSE(diagnostic.manualCheckRequired);
    EXPECT_EQ(diagnostic.confirmedSteps,
              static_cast<uint32_t>(MigrationStep::LibvirtTransferred) |
                  static_cast<uint32_t>(MigrationStep::DestinationDataAccepted) |
                  static_cast<uint32_t>(MigrationStep::SourceTsbCommitted) |
                  static_cast<uint32_t>(MigrationStep::DestinationConfirmed) |
                  static_cast<uint32_t>(MigrationStep::SourceVRootRemoved) |
                  static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined));
    EXPECT_EQ(State().sourceCompletionOrder,
              (std::vector<std::string>{"source-tsb-committed", "destination-success-reply", "source-remove",
                                        "source-undefine"}));
    EXPECT_EQ(State().removeCalls, 1);
    EXPECT_EQ(State().undefineCalls, 1);
}

// 可信资源删除前两次失败，第三次成功后才允许取消定义。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRetriesVrootBeforeUndefine)
{
    State().removeFailuresRemaining = 2;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::OK);
    EXPECT_EQ(State().removeCalls, 3);
    EXPECT_EQ(State().undefineCalls, 1);
    EXPECT_EQ(State().sourceCompletionOrder.back(), "source-undefine");
}

// 可信资源删除达到次数上限后，保留源端定义并向调用方报告错误。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupStopsWhenVrootAttemptsExhausted)
{
    State().removeFailuresRemaining = 4;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 3);
    EXPECT_EQ(State().undefineCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Partial);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::SourceCleanup);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::RemoveVRoot);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
    EXPECT_NE(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::DestinationConfirmed), 0U);
    EXPECT_EQ(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::SourceVRootRemoved), 0U);
}

// 守护进程配置会限制本次源端清理的总尝试次数。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupUsesConfiguredAttemptLimit)
{
    struct RestoreConfig {
        LinkConfig original = ConfigMgr::Instance().GetLinkConfig();
        ~RestoreConfig() { ConfigMgr::Instance().SetLinkConfig(original); }
    } restore;
    LinkConfig config{};
    config.sourceCleanupMaxAttempts = 1;
    ConfigMgr::Instance().SetLinkConfig(config);
    State().removeFailuresRemaining = 2;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 1);
    EXPECT_EQ(State().undefineCalls, 0);
}

// 直接构造会话时也必须拒绝零次清理，不能跳过 VRoot 而直接取消定义。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRejectsInvalidDirectConfiguration)
{
    struct RestoreConfig {
        LinkConfig original = ConfigMgr::Instance().GetLinkConfig();
        ~RestoreConfig() { ConfigMgr::Instance().SetLinkConfig(original); }
    } restore;
    LinkConfig config{};
    config.sourceCleanupMaxAttempts = 0;
    ConfigMgr::Instance().SetLinkConfig(config);
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
}

// 可信资源已经删除，取消定义失败时只重试该步骤，不反向补偿目的端。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupReportsUndefineExhaustion)
{
    State().undefineFailuresRemaining = 4;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 1);
    EXPECT_EQ(State().undefineCalls, 3);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Partial);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::UndefineDomain);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Libvirt);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -1);
    EXPECT_NE(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::SourceVRootRemoved), 0U);
    EXPECT_EQ(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::SourceDefinitionUndefined), 0U);
}

TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRetriesUndefineAfterVrootRemoval)
{
    State().undefineFailuresRemaining = 2;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::OK);
    EXPECT_EQ(State().removeCalls, 1);
    EXPECT_EQ(State().undefineCalls, 3);
    EXPECT_EQ(State().clientNotifyCalls, 1);
}

TEST_F(DestinationMigrationAdmissionTest, SourceWithoutUndefineFlagKeepsBothLocalResources)
{
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::OK);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, SourceUsesOneAttemptIdAcrossFivePeerStages)
{
    State().acceptSuccessNotification = true;
    ASSERT_EQ(RunMockSource(), MigrateSessionRc::OK);
    ASSERT_EQ(State().sourceAttemptIds.size(), 5U);
    ASSERT_EQ(State().sourceAttemptIds.front().size(), 32U);
    for (const auto &id : State().sourceAttemptIds) {
        EXPECT_EQ(id, State().sourceAttemptIds.front());
    }
}

TEST_F(DestinationMigrationAdmissionTest, RejectedDestinationConfirmationPreservesSourceResources)
{
    State().rejectSourceFinish = true;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, DuplicateVrootDiagnosticDoesNotUndefineExistingDestination)
{
    State().sourceDuplicateTransfer = true;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    // 底层重复 UUID 码只在诊断字段中，不能因业务 result=1 而误删既有目的端定义。
    EXPECT_EQ(State().undefineCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, TransferTransportFailureKeepsPrimaryAndListsCompensationFailures)
{
    State().sourceTransferTransportFailure = true;
    State().undefineFailuresRemaining = 1;
    State().failSourceFailureNotify = true;
    State().failSourceFailurePeerNotify = true;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_NE(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::LibvirtTransferred), 0U);
    ASSERT_EQ(diagnostic.compensationErrors.size(), 3U);
    EXPECT_EQ(diagnostic.compensationErrors[0].operation, MigrationOperation::UndefineDomain);
    EXPECT_EQ(diagnostic.compensationErrors[1].operation, MigrationOperation::NotifyTsb);
    EXPECT_EQ(diagnostic.compensationErrors[2].operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(State().undefineCalls, 1);
    EXPECT_EQ(State().clientNotifyCalls, 1);
}

// 最终 RPC 没有返回业务结果时，不推测目的端状态，也不启动源端删除。
TEST_F(DestinationMigrationAdmissionTest, LostFinalReplyPreservesSourceResources)
{
    State().failSourceFinishTransport = true;
    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DestinationCommit);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyPeer);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Grpc);
    EXPECT_NE(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::SourceTsbCommitted), 0U);
    EXPECT_EQ(diagnostic.confirmedSteps & static_cast<uint32_t>(MigrationStep::DestinationConfirmed), 0U);
}

// 同名虚机的 UUID 发生变化时，不删除原 UUID 的可信资源，也不取消新虚机的定义。
TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRejectsChangedDefinitionIdentity)
{
    auto &lookupUuid = Libvirt::GetInstance().virDomainGetUUIDString;
    struct RestoreUuid {
        decltype(lookupUuid) target;
        std::remove_reference_t<decltype(lookupUuid)> original;
        ~RestoreUuid() { target = original; }
    } restore{lookupUuid, lookupUuid};
    lookupUuid = decltype(restore.original)("virDomainGetUUIDString", ReturnDifferentSourceUuid);

    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
}

TEST_F(DestinationMigrationAdmissionTest, SourceCleanupRejectsUnreadableDefinitionIdentity)
{
    auto &lookupUuid = Libvirt::GetInstance().virDomainGetUUIDString;
    struct RestoreUuid {
        decltype(lookupUuid) target;
        std::remove_reference_t<decltype(lookupUuid)> original;
        ~RestoreUuid() { target = original; }
    } restore{lookupUuid, lookupUuid};
    lookupUuid = decltype(restore.original)("virDomainGetUUIDString", FailSourceUuidLookup);

    EXPECT_EQ(RunSourceWithObservedUndefine(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().removeCalls, 0);
    EXPECT_EQ(State().undefineCalls, 0);
}

TEST_F(DestinationMigrationAdmissionTest, SourceTsbSuccessFailureCannotBeReportedAsSuccess)
{
    State().failSourceSuccessNotify = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().successNotificationCalls, 1);
    EXPECT_EQ(State().clientNotifyCalls, 0);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::SourceCommit);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::NotifyTsb);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, -1);
}

TEST_F(DestinationMigrationAdmissionTest, SourceCipherFetchFailureKeepsTsbCode)
{
    State().failSourceCipherFetch = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    EXPECT_EQ(diagnostic.outcome, MigrationOutcome::Unknown);
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCipher);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
    EXPECT_TRUE(diagnostic.manualCheckRequired);
}

TEST_F(DestinationMigrationAdmissionTest, SourceRejectsZeroLengthCipherBeforeLibvirtTransfer)
{
    State().injectSourceCipherLength = true;
    State().sourceCipherLength = 0;
    ScopedSourceMigrationCounter migration;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    EXPECT_EQ(State().sourceMigrateCalls, 0);
    EXPECT_EQ(State().sourceDataCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCipher);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
    EXPECT_FALSE(diagnostic.primaryError.hasRawCode);
}

TEST_F(DestinationMigrationAdmissionTest, SourceRejectsNegativeLengthCipherBeforeLibvirtTransfer)
{
    State().injectSourceCipherLength = true;
    State().sourceCipherLength = -1;
    ScopedSourceMigrationCounter migration;
    MigrateSessionRc result = MigrateSessionRc::OK;
    EXPECT_NO_THROW(result = RunMockSource());
    EXPECT_EQ(result, MigrateSessionRc::ERROR);
    EXPECT_EQ(State().sourceMigrateCalls, 0);
    EXPECT_EQ(State().sourceDataCalls, 0);
    EXPECT_EQ(State().clientNotifyCalls, 1);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetCipher);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Internal);
}

TEST_F(DestinationMigrationAdmissionTest, SourceKeyImportFailureKeepsTsbCode)
{
    State().failSourceKeyImport = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::KeyExchange);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::ExchangeKey);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
}

TEST_F(DestinationMigrationAdmissionTest, SourceDescriptionFetchFailureKeepsTsbCode)
{
    State().failSourceDescriptionFetch = true;
    EXPECT_EQ(RunMockSource(), MigrateSessionRc::ERROR);
    const auto &diagnostic = State().lastSourceDiagnostic;
    ASSERT_TRUE(diagnostic.hasPrimaryError);
    EXPECT_EQ(diagnostic.primaryError.stage, MigrationStage::DataTransfer);
    EXPECT_EQ(diagnostic.primaryError.side, MigrationSide::Source);
    EXPECT_EQ(diagnostic.primaryError.operation, MigrationOperation::GetDescription);
    EXPECT_EQ(diagnostic.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(diagnostic.primaryError.hasRawCode);
    EXPECT_EQ(diagnostic.primaryError.rawCode, ERR_FILE_LOCK);
}

// 在 libvirt mock 内手动触发阶段超时，验证源端未提前清理，并在调用返回后发出最终通知。
TEST_F(DestinationMigrationAdmissionTest, SourceTimeoutInsideLibvirtWaitsForFinalization)
{
    auto &migration = Libvirt::GetInstance().virDomainMigrate3;
    struct RestoreMigration {
        decltype(migration) target;
        std::remove_reference_t<decltype(migration)> original;
        ~RestoreMigration() { target = original; }
    } restore{migration, migration};
    migration = decltype(restore.original)("virDomainMigrate3", ExpireSourceInsideLibvirt);

    EXPECT_EQ(RunMockSource(), MigrateSessionRc::OK);
    EXPECT_TRUE(State().sourceTimeoutObservedInLibvirt);
    EXPECT_EQ(State().clientNotifyCalls, 1);
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
        request.set_attempt_id(virtrust::TestAttemptId(request.uuid()));
        virtrust::protos::EXchangePkAndReportReply reply;
        virtrust::State().cleanupProbeResult = session->OnExchangeKeyRequestReceived(&request, &reply);
    }
    RealDestinationCleanup(session);
}

extern "C" virtrust::MigrationResult RealDestinationDiagnostic(const virtrust::MigrationSession *)
    asm("__real__ZNK8virtrust16MigrationSession10DiagnosticEv");
extern "C" virtrust::MigrationResult WrappedDestinationDiagnostic(const virtrust::MigrationSession *)
    asm("__wrap__ZNK8virtrust16MigrationSession10DiagnosticEv");
extern "C" virtrust::MigrationResult WrappedDestinationDiagnostic(const virtrust::MigrationSession *session)
{
    if (virtrust::State().throwOnDiagnostic) {
        throw std::bad_alloc();
    }
    return RealDestinationDiagnostic(session);
}

extern "C" void RealDestinationToProto(const virtrust::MigrationResult &, virtrust::protos::MigrationDiagnostic *)
    asm("__real__ZN8virtrust7ToProtoERKNS_15MigrationResultEPNS_6protos19MigrationDiagnosticE");
extern "C" void WrappedDestinationToProto(const virtrust::MigrationResult &, virtrust::protos::MigrationDiagnostic *)
    asm("__wrap__ZN8virtrust7ToProtoERKNS_15MigrationResultEPNS_6protos19MigrationDiagnosticE");
extern "C" void WrappedDestinationToProto(const virtrust::MigrationResult &diagnostic,
                                            virtrust::protos::MigrationDiagnostic *reply)
{
    if (virtrust::State().throwOnDiagnosticSerialization) {
        throw std::bad_alloc();
    }
    RealDestinationToProto(diagnostic, reply);
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
    virtrust::State().sourceAttemptIds.push_back(request.attempt_id());
    if (virtrust::State().failSourcePrepareTransport) {
        ++virtrust::State().clientPrepareCalls;
        // 未收到业务回复时，零值 result 不得被源端解释为成功。
        response->set_result(0);
        return -1;
    }
    if (virtrust::State().expireSourceDuringPrepare) {
        ++virtrust::State().clientPrepareCalls;
        EXPECT_EQ(virtrust::State().timerCallbacks.size(), 1U);
        EXPECT_NE(virtrust::SessionManager::GetInstance().GetSession(request.uuid()), nullptr);
        if (!virtrust::State().timerCallbacks.empty()) {
            virtrust::State().timerCallbacks.front()();
        }
        EXPECT_NE(virtrust::SessionManager::GetInstance().GetSession(request.uuid()), nullptr);
        virtrust::NodeAdmission ordinary;
        EXPECT_EQ(ordinary.TryAcquire(virtrust::AdmissionKind::OrdinaryMutation, virtrust::State().directory,
                                      geteuid()), virtrust::LockOutcome::Busy);
        // 模拟调用返回后的两种结果；超时不能抢占 RPC，也不能提前放开资格。
        response->set_result(virtrust::State().acceptPrepareAfterSourceTimeout ? 0
                            : static_cast<uint32_t>(virtrust::VirtrustRc::ERROR));
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

extern "C" int32_t RealDestinationClientExchange(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::EXchangePkAndReportRequest &, virtrust::protos::EXchangePkAndReportReply *)
    asm("__real__ZN8virtrust13RpcClientMock19ExchangePkAndReportEjRKNS_6protos26EXchangePkAndReportRequestEPNS1_24EXchangePkAndReportReplyE");
extern "C" int32_t WrappedDestinationClientExchange(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::EXchangePkAndReportRequest &, virtrust::protos::EXchangePkAndReportReply *)
    asm("__wrap__ZN8virtrust13RpcClientMock19ExchangePkAndReportEjRKNS_6protos26EXchangePkAndReportRequestEPNS1_24EXchangePkAndReportReplyE");
extern "C" int32_t WrappedDestinationClientExchange(virtrust::RpcClientMock *self, uint32_t timeout,
    const virtrust::protos::EXchangePkAndReportRequest &request, virtrust::protos::EXchangePkAndReportReply *response)
{
    virtrust::State().sourceAttemptIds.push_back(request.attempt_id());
    if (virtrust::State().failSourceExchangeTransport) {
        return virtrust::RPC_TRANSPORT_FAILURE;
    }
    if (virtrust::State().failSourceExchangeBusiness) {
        response->set_result(static_cast<uint32_t>(virtrust::VirtrustRc::ERROR));
        auto *error = response->mutable_diagnostic()->mutable_primary_error();
        error->set_stage(virtrust::protos::MIGRATION_STAGE_KEY_EXCHANGE);
        error->set_side(virtrust::protos::MIGRATION_SIDE_DESTINATION);
        error->set_operation(virtrust::protos::MIGRATION_OPERATION_GET_REPORT);
        error->set_origin(virtrust::protos::MIGRATION_ERROR_ORIGIN_TSB);
        error->set_has_raw_code(true);
        error->set_raw_code(ERR_FILE_LOCK);
        return static_cast<int32_t>(virtrust::VirtrustRc::ERROR);
    }
    const auto result = RealDestinationClientExchange(self, timeout, request, response);
    if (result == 0 && response->result() == 0 && virtrust::State().replaceSourceExchangeReplyUuid) {
        response->set_uuid("12345678-1234-1234-1234-123456789099");
        virtrust::State().wrongReplyDelivered = true;
    }
    return result;
}

extern "C" int32_t RealDestinationClientStart(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::StartMigRequest &, virtrust::protos::StartMigReply *)
    asm("__real__ZN8virtrust13RpcClientMock14StartMigrationEjRKNS_6protos15StartMigRequestEPNS1_13StartMigReplyE");
extern "C" int32_t WrappedDestinationClientStart(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::StartMigRequest &, virtrust::protos::StartMigReply *)
    asm("__wrap__ZN8virtrust13RpcClientMock14StartMigrationEjRKNS_6protos15StartMigRequestEPNS1_13StartMigReplyE");
extern "C" int32_t WrappedDestinationClientStart(virtrust::RpcClientMock *self, uint32_t timeout,
    const virtrust::protos::StartMigRequest &request, virtrust::protos::StartMigReply *response)
{
    virtrust::State().sourceAttemptIds.push_back(request.attempt_id());
    if (virtrust::State().failSourceStartTransport) {
        return virtrust::RPC_TRANSPORT_FAILURE;
    }
    return RealDestinationClientStart(self, timeout, request, response);
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
    virtrust::State().sourceAttemptIds.push_back(request.attempt_id());
    // 无论走哪条注入分支，都统计最终通知调用，避免未调用断言被默认 mock 路径掩盖。
    ++virtrust::State().clientNotifyCalls;
    if (virtrust::State().failSourceFailurePeerNotify && request.result() != 0) {
        return -1;
    }
    if (virtrust::State().failSourceFinishTransport) {
        EXPECT_EQ(request.result(), 0U);
        return -1;
    }
    if (virtrust::State().rejectSourceFinish) {
        EXPECT_EQ(request.result(), 0U);
        response->set_result(1);
        auto *error = response->mutable_diagnostic()->mutable_primary_error();
        error->set_stage(virtrust::protos::MIGRATION_STAGE_DESTINATION_COMMIT);
        error->set_side(virtrust::protos::MIGRATION_SIDE_DESTINATION);
        error->set_operation(virtrust::protos::MIGRATION_OPERATION_NOTIFY_TSB);
        error->set_origin(virtrust::protos::MIGRATION_ERROR_ORIGIN_TSB);
        error->set_has_raw_code(true);
        error->set_raw_code(ERR_FILE_LOCK);
        // 生产客户端会把目的端业务结果作为方法返回值交给源端。
        return response->result();
    }
    if (virtrust::State().acceptPrepareAfterSourceTimeout) {
        EXPECT_EQ(request.result(), 0U);
        response->set_result(0);
        virtrust::State().sourceCompletionOrder.push_back("destination-success-reply");
        return 0;
    }
    int32_t result = 0;
    if (!virtrust::State().useRealClientPrepare) {
        result = RealDestinationClientNotify(self, timeout, request, response);
    } else {
        virtrust::MigrationServiceImpl service;
        result = service.NotifyVRMigrateResult(nullptr, &request, response).ok() ? 0 : -1;
    }
    if (request.result() == 0 && result == 0 && response->result() == 0) {
        virtrust::State().sourceCompletionOrder.push_back("destination-success-reply");
    }
    return result;
}

extern "C" int32_t RealDestinationClientTransfer(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::VRsourceInfoRequest &, virtrust::protos::VRsourceInfoReply *)
    asm("__real__ZN8virtrust13RpcClientMock16SendVRsourceDataEjRKNS_6protos19VRsourceInfoRequestEPNS1_17VRsourceInfoReplyE");
extern "C" int32_t WrappedDestinationClientTransfer(virtrust::RpcClientMock *, uint32_t,
    const virtrust::protos::VRsourceInfoRequest &, virtrust::protos::VRsourceInfoReply *)
    asm("__wrap__ZN8virtrust13RpcClientMock16SendVRsourceDataEjRKNS_6protos19VRsourceInfoRequestEPNS1_17VRsourceInfoReplyE");
extern "C" int32_t WrappedDestinationClientTransfer(virtrust::RpcClientMock *self, uint32_t timeout,
    const virtrust::protos::VRsourceInfoRequest &request, virtrust::protos::VRsourceInfoReply *response)
{
    virtrust::State().sourceAttemptIds.push_back(request.attempt_id());
    ++virtrust::State().sourceDataCalls;
    if (virtrust::State().sourceTransferTransportFailure) {
        return -1;
    }
    if (virtrust::State().sourceDuplicateTransfer) {
        response->set_result(static_cast<uint32_t>(virtrust::VirtrustRc::ERROR));
        auto *error = response->mutable_diagnostic()->mutable_primary_error();
        error->set_stage(virtrust::protos::MIGRATION_STAGE_DATA_TRANSFER);
        error->set_side(virtrust::protos::MIGRATION_SIDE_DESTINATION);
        error->set_operation(virtrust::protos::MIGRATION_OPERATION_CREATE_VROOT);
        error->set_origin(virtrust::protos::MIGRATION_ERROR_ORIGIN_TSB);
        error->set_has_raw_code(true);
        error->set_raw_code(ERR_DUPLICATE_UUID);
        return static_cast<int32_t>(virtrust::VirtrustRc::ERROR);
    }
    return RealDestinationClientTransfer(self, timeout, request, response);
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

extern "C" int RealSourceDescriptionFetch(int *, Description **) asm("__real_GetVRoots");
extern "C" int WrappedSourceDescriptionFetch(int *, Description **) asm("__wrap_GetVRoots");
extern "C" int WrappedSourceDescriptionFetch(int *count, Description **items)
{
    if (virtrust::State().failSourceDescriptionFetch) {
        return ERR_FILE_LOCK;
    }
    if (virtrust::State().forcedRootCount >= 0) {
        *count = virtrust::State().forcedRootCount;
        *items = *count == 0 ? nullptr :
            static_cast<Description *>(calloc(static_cast<size_t>(*count), sizeof(Description)));
        return *count == 0 || *items != nullptr ? 0 : -1;
    }
    return RealSourceDescriptionFetch(count, items);
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

extern "C" int RealDestinationCreateVRoot(Description *) asm("__real_CreateVRoot");
extern "C" int WrappedDestinationCreateVRoot(Description *) asm("__wrap_CreateVRoot");
extern "C" int WrappedDestinationCreateVRoot(Description *description)
{
    ++virtrust::State().createVRootCalls;
    return RealDestinationCreateVRoot(description);
}

extern "C" int RealSourceCipherFetch(char *, char *, char **, int *)
    asm("__real_MigrationGetVrootCipher");
extern "C" int WrappedSourceCipherFetch(char *, char *, char **, int *)
    asm("__wrap_MigrationGetVrootCipher");
extern "C" int WrappedSourceCipherFetch(char *physicalUuid, char *virtualUuid, char **cipher, int *length)
{
    if (virtrust::State().failSourceCipherFetch) {
        return ERR_FILE_LOCK;
    }
    const int result = RealSourceCipherFetch(physicalUuid, virtualUuid, cipher, length);
    if (result == 0 && virtrust::State().injectSourceCipherLength) {
        *length = virtrust::State().sourceCipherLength;
    }
    return result;
}

extern "C" int RealDestinationMigrationNotify(char *, int) asm("__real_MigrationNotify");
extern "C" int WrappedDestinationMigrationNotify(char *, int) asm("__wrap_MigrationNotify");
extern "C" int WrappedDestinationMigrationNotify(char *uuid, int status)
{
    if (status != 0 && virtrust::State().failSourceFailureNotify) {
        return ERR_FILE_LOCK;
    }
    if (status == 0) {
        ++virtrust::State().successNotificationCalls;
        if (virtrust::State().failSourceSuccessNotify) {
            return -1;
        }
        const int result = virtrust::State().acceptSuccessNotification ? 0 : RealDestinationMigrationNotify(uuid, status);
        if (result == 0 && std::string_view(uuid) == "12345678-1234-1234-1234-123456789002") {
            virtrust::State().sourceCompletionOrder.push_back("source-tsb-committed");
        }
        return result;
    }
    return RealDestinationMigrationNotify(uuid, status);
}

extern "C" int RealDestinationRemoveVRoot(char *) asm("__real_RemoveVRoot");
extern "C" int WrappedDestinationRemoveVRoot(char *) asm("__wrap_RemoveVRoot");
extern "C" int WrappedDestinationRemoveVRoot(char *uuid)
{
    auto &state = virtrust::State();
    EXPECT_STREQ(uuid, "12345678-1234-1234-1234-123456789002");
    state.sourceCompletionOrder.push_back("source-remove");
    ++state.removeCalls;
    if (state.removeFailuresRemaining > 0) {
        --state.removeFailuresRemaining;
        return ERR_FILE_LOCK;
    }
    return RealDestinationRemoveVRoot(uuid);
}

extern "C" int RealDestinationGetReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__real_GetReport");
extern "C" int WrappedDestinationGetReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__wrap_GetReport");
extern "C" int WrappedDestinationGetReport(char *physicalUuid, char *virtualUuid,
    trust_report_new *hostReport, trust_report_new *vmReport)
{
    ++virtrust::State().getReportCalls;
    if (virtrust::State().failGetReport) {
        return -72;
    }
    const int result = RealDestinationGetReport(physicalUuid, virtualUuid, hostReport, vmReport);
    if (result == 0 && hostReport != nullptr && vmReport != nullptr) {
        // 现有 mock 的 GetReport 返回成功但不写输出；测试在序列化前补齐确定性数据。
        *hostReport = {};
        *vmReport = {};
    }
    return result;
}

extern "C" int RealDestinationGetCert(char *, char **, int *, char **, int *) asm("__real_MigrationGetCert");
extern "C" int WrappedDestinationGetCert(char *, char **, int *, char **, int *) asm("__wrap_MigrationGetCert");
extern "C" int WrappedDestinationGetCert(char *uuid, char **cert, int *certLen, char **pubKey, int *pubKeyLen)
{
    if (virtrust::State().failGetCert) {
        return -71;
    }
    const int result = RealDestinationGetCert(uuid, cert, certLen, pubKey, pubKeyLen);
    if (result == 0 && (virtrust::State().certLengthOverride != INT_MIN ||
                        virtrust::State().publicKeyLengthOverride != INT_MIN)) {
        virtrust::State().trackedCert = *cert;
        virtrust::State().trackedPublicKey = *pubKey;
        if (virtrust::State().certLengthOverride != INT_MIN) {
            *certLen = virtrust::State().certLengthOverride;
        }
        if (virtrust::State().publicKeyLengthOverride != INT_MIN) {
            *pubKeyLen = virtrust::State().publicKeyLengthOverride;
        }
    }
    return result;
}

extern "C" void __real_free(void *);
// 只统计测试中由 MigrationGetCert 返回的两个缓冲区，其他 free 仍透传原函数。
extern "C" void __wrap_free(void *memory)
{
    if (memory != nullptr && memory == virtrust::State().trackedCert) {
        ++virtrust::State().certFreeCalls;
    }
    if (memory != nullptr && memory == virtrust::State().trackedPublicKey) {
        ++virtrust::State().publicKeyFreeCalls;
    }
    __real_free(memory);
}

extern "C" int RealDestinationCheckPeerPk(char *, char *, char *) asm("__real_MigrationCheckPeerPk");
extern "C" int WrappedDestinationCheckPeerPk(char *, char *, char *) asm("__wrap_MigrationCheckPeerPk");
extern "C" int WrappedDestinationCheckPeerPk(char *uuid, char *cert, char *publicKey)
{
    if (virtrust::State().wrongReplyDelivered) {
        ++virtrust::State().postWrongReplyCertificateCalls;
    }
    if (virtrust::State().failPeerCertificate) {
        return -73;
    }
    return RealDestinationCheckPeerPk(uuid, cert, publicKey);
}

extern "C" int RealDestinationVerifyReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__real_VerifyTrustReport");
extern "C" int WrappedDestinationVerifyReport(char *, char *, trust_report_new *, trust_report_new *)
    asm("__wrap_VerifyTrustReport");
extern "C" int WrappedDestinationVerifyReport(char *physicalUuid, char *virtualUuid,
    trust_report_new *hostReport, trust_report_new *vmReport)
{
    if (virtrust::State().wrongReplyDelivered) {
        ++virtrust::State().postWrongReplyReportChecks;
    }
    if (virtrust::State().failPeerReport) {
        return -74;
    }
    return RealDestinationVerifyReport(physicalUuid, virtualUuid, hostReport, vmReport);
}

extern "C" int RealDestinationTransDupPub(int, char *, char **, int *, char *, int)
    asm("__real_TransDupPub");
extern "C" int WrappedDestinationTransDupPub(int, char *, char **, int *, char *, int)
    asm("__wrap_TransDupPub");
extern "C" int WrappedDestinationTransDupPub(int direction, char *uuid, char **key, int *keyLength,
    char *input, int inputLength)
{
    if (virtrust::State().wrongReplyDelivered && direction == EN_IMPORT) {
        ++virtrust::State().postWrongReplyKeyImports;
    }
    if (virtrust::State().failKeyExport && direction == EN_EXPORT) {
        return -75;
    }
    if (virtrust::State().failSourceKeyImport && direction == EN_IMPORT) {
        return ERR_FILE_LOCK;
    }
    return RealDestinationTransDupPub(direction, uuid, key, keyLength, input, inputLength);
}
