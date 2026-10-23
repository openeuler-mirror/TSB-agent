/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

#include "virtrust/api/domain.h"
#include "virtrust/api/defines.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/migration_service_impl.h"
#include "virtrust/link/migration_destination_uri.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
namespace {
constexpr const char *UUID = "12345678-1234-1234-1234-123456789002";

struct SourceTestState {
    std::string directory;
    int admissionCalls = 0;
    int startCalls = 0;
    bool startSawExclusive = false;
    bool cleanupSawExclusive = false;
    bool throwOnAcquire = false;
    bool throwOnStart = false;
    bool throwOnCleanup = false;
    bool replaceBeforeCleanupFailure = false;
    std::shared_ptr<MigrationSession> replacement;
    bool useRealStart = false;
    MigrateSessionRc startResult = MigrateSessionRc::OK;
};

SourceTestState &State()
{
    static SourceTestState state;
    return state;
}

// 仅在本测试进程替换 libvirt 查询入口，析构时恢复全局 mock 函数。
class ScopedDomainListFailure {
public:
    ScopedDomainListFailure() : original_(Libvirt::GetInstance().virConnectListAllDomains)
    {
        Libvirt::GetInstance().virConnectListAllDomains =
            DlFun<int, virConnectPtr, virDomainPtr **, unsigned int>("virConnectListAllDomains",
                +[](virConnectPtr, virDomainPtr **, unsigned int) { return -1; });
    }
    ~ScopedDomainListFailure()
    {
        Libvirt::GetInstance().virConnectListAllDomains = original_;
    }
    ScopedDomainListFailure(const ScopedDomainListFailure &) = delete;
    ScopedDomainListFailure &operator=(const ScopedDomainListFailure &) = delete;

private:
    DlFun<int, virConnectPtr, virDomainPtr **, unsigned int> original_;
};

// 若在准入前打开 libvirt 连接，此探针会使原本应为 Busy 的请求变成 Error。
class ScopedSourceConnectFailure {
public:
    ScopedSourceConnectFailure() : original_(Libvirt::GetInstance().virConnectOpen)
    {
        calls_ = 0;
        Libvirt::GetInstance().virConnectOpen =
            DlFun<virConnectPtr, const char *>("virConnectOpen", +[](const char *) -> virConnectPtr {
                ++calls_;
                return nullptr;
            });
    }
    ~ScopedSourceConnectFailure()
    {
        Libvirt::GetInstance().virConnectOpen = original_;
    }
    ScopedSourceConnectFailure(const ScopedSourceConnectFailure &) = delete;
    ScopedSourceConnectFailure &operator=(const ScopedSourceConnectFailure &) = delete;
    int Calls() const { return calls_; }

private:
    inline static int calls_ = 0;
    DlFun<virConnectPtr, const char *> original_;
};

class SourceMigrationAdmissionTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        char path[] = "/tmp/virtrust-source-admission-XXXXXX";
        const char *created = mkdtemp(path);
        ASSERT_NE(created, nullptr);
        root_ = created;
        State() = {};
        State().directory = root_ + "/runtime";
        request_.set_domainname("test-domain-2");
        request_.set_uuid(UUID);
        request_.set_desturi("qemu+tls://192.168.1.100/system");
        request_.set_localuri("qemu:///system");
        request_.set_flags(VIR_MIGRATE_OFFLINE | VIR_MIGRATE_PERSIST_DEST | MIGRATE_UNDEFINE_SOURCE);
    }

    void TearDown() override
    {
        Logger::Instance()->Reset();
        // 负例可能改写请求 UUID；先报告残留，再清理本用例涉及的两种身份。
        auto &manager = SessionManager::GetInstance();
        EXPECT_EQ(manager.GetSession(request_.uuid()), nullptr);
        manager.RemoveSession(request_.uuid());
        if (request_.uuid() != UUID) {
            EXPECT_EQ(manager.GetSession(UUID), nullptr);
            manager.RemoveSession(UUID);
        }
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        EXPECT_FALSE(error) << error.message();
        State() = {};
    }

    uint32_t Migrate()
    {
        return MigrateReply().result();
    }

    protos::DomainMigraterReply MigrateReply()
    {
        protos::DomainMigraterReply reply;
        const auto status = service_.DomainMigrate(nullptr, &request_, &reply);
        EXPECT_TRUE(status.ok());
        return reply;
    }

    std::string root_;
    MigrationServiceImpl service_;
    protos::DomainMigraterRequest request_;
};

TEST_F(SourceMigrationAdmissionTest, NullRequestOrReplyIsRejectedBeforeAdmission)
{
    grpc::ServerContext context;
    protos::DomainMigraterReply reply;
    const auto missingRequest = service_.DomainMigrate(&context, nullptr, &reply);
    const auto missingReply = service_.DomainMigrate(&context, &request_, nullptr);
    EXPECT_EQ(missingRequest.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(missingReply.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, OrdinaryHolderReturnsBusyBeforeCreatingSession)
{
    NodeAdmission ordinary;
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
    ScopedSourceConnectFailure failIfQueriedBeforeAdmission;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::BUSY));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(reply.diagnostic().primary_error().operation(), protos::MIGRATION_OPERATION_ACQUIRE_ADMISSION);
    EXPECT_FALSE(reply.diagnostic().manual_check_required());
    EXPECT_EQ(State().admissionCalls, 1);
    EXPECT_EQ(failIfQueriedBeforeAdmission.Calls(), 0);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, BusySurvivesDiagnosticFailure)
{
    NodeAdmission ordinary;
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::ERROR) {
            throw std::bad_alloc();
        }
    });
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::BUSY));
    EXPECT_EQ(State().startCalls, 0);
}

TEST_F(SourceMigrationAdmissionTest, ChangedUuidFailsPrecheckAndReleasesAdmission)
{
    request_.set_uuid("12345678-1234-1234-1234-123456789099");
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(reply.diagnostic().primary_error().operation(), protos::MIGRATION_OPERATION_VALIDATE);
    EXPECT_FALSE(reply.diagnostic().manual_check_required());
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(request_.uuid()), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, LibvirtListFailureReportsQueryOriginBeforeSession)
{
    ScopedDomainListFailure failedList;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    const auto &error = reply.diagnostic().primary_error();
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    EXPECT_EQ(error.stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(error.operation(), protos::MIGRATION_OPERATION_LOOKUP_DOMAIN);
    EXPECT_EQ(error.origin(), protos::MIGRATION_ERROR_ORIGIN_LIBVIRT);
    EXPECT_TRUE(error.has_raw_code());
    EXPECT_EQ(error.raw_code(), -1);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, ChangedNameWithSameUuidFailsPrecheck)
{
    request_.set_domainname("test-domain-1");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 1);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(request_.uuid()), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, RunningDomainFailsPrecheck)
{
    request_.set_domainname("running-domain");
    request_.set_uuid("12345678-1234-1234-1234-123456789003");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(request_.uuid()), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, InvalidSourceUriFailsBeforeSessionAndReleasesAdmission)
{
    request_.set_localuri("");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, RejectsRemoteSourceBeforeAdmissionAndLibvirtQuery)
{
    request_.set_localuri("qemu+ssh://remote.example.com/system");
    ScopedSourceConnectFailure failIfRemoteIsOpened;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(failIfRemoteIsOpened.Calls(), 0);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, RejectsDestinationHostnameEvenIfQueryContainsIp)
{
    request_.set_desturi("qemu+tls://remote.example.com/system?hint=192.168.1.100");
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(reply.diagnostic().primary_error().operation(), protos::MIGRATION_OPERATION_VALIDATE);
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
}

TEST_F(SourceMigrationAdmissionTest, RejectsDestinationWithInvalidIpv4Octet)
{
    request_.set_desturi("qemu+tls://999.168.1.100/system");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
}

TEST_F(SourceMigrationAdmissionTest, RejectsDestinationWithEmbeddedSecondAddress)
{
    request_.set_desturi("qemu+tls://192.168.1.100/system?target=10.0.0.1");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
}

TEST_F(SourceMigrationAdmissionTest, RejectsDestinationWithMalformedPort)
{
    request_.set_desturi("qemu+tls://192.168.1.100:70000/system");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
}

// 非法标志必须在取得节点资格和访问 libvirt 之前被本机 UDS 入口拒绝。
TEST_F(SourceMigrationAdmissionTest, RejectsUnsupportedFlagsBeforeAdmissionAndLibvirt)
{
    const unsigned int supportedFlags = VIR_MIGRATE_OFFLINE | VIR_MIGRATE_PERSIST_DEST | MIGRATE_UNDEFINE_SOURCE;
    for (const unsigned int flags : {0U, supportedFlags & ~MIGRATE_UNDEFINE_SOURCE,
                                     supportedFlags & ~VIR_MIGRATE_OFFLINE,
                                     supportedFlags & ~VIR_MIGRATE_PERSIST_DEST,
                                     supportedFlags | (1U << 31)}) {
        SCOPED_TRACE(::testing::Message() << "flags=" << flags);
        request_.set_flags(flags);
        ScopedSourceConnectFailure failIfOpened;
        const auto reply = MigrateReply();
        EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
        ASSERT_TRUE(reply.has_diagnostic());
        EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
        EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
        EXPECT_EQ(reply.diagnostic().primary_error().side(), protos::MIGRATION_SIDE_SOURCE);
        EXPECT_EQ(reply.diagnostic().primary_error().operation(), protos::MIGRATION_OPERATION_VALIDATE);
        EXPECT_EQ(reply.diagnostic().primary_error().origin(), protos::MIGRATION_ERROR_ORIGIN_VALIDATION);
        EXPECT_EQ(reply.diagnostic().confirmed_steps(), 0U);
        EXPECT_FALSE(reply.diagnostic().manual_check_required());
        EXPECT_EQ(State().admissionCalls, 0);
        EXPECT_EQ(State().startCalls, 0);
        EXPECT_EQ(failIfOpened.Calls(), 0);
        EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    }
}

// 诊断日志失败不能改变已确定的非法标志预检查结果。
TEST_F(SourceMigrationAdmissionTest, UnsupportedFlagsRemainPreflightFailureWhenLoggingThrows)
{
    request_.set_flags(0);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::ERROR) {
            throw std::bad_alloc();
        }
    });
    const auto reply = MigrateReply();
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_FAILED_BEFORE_EFFECT);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(reply.diagnostic().primary_error().operation(), protos::MIGRATION_OPERATION_VALIDATE);
    EXPECT_FALSE(reply.diagnostic().manual_check_required());
    EXPECT_EQ(State().admissionCalls, 0);
    EXPECT_EQ(State().startCalls, 0);
}

TEST_F(SourceMigrationAdmissionTest, InvalidDestinationCredentialsAreNotLogged)
{
    std::vector<std::string> messages;
    Logger::Instance()->SetCustomLogFunction([&messages](LogLevel, std::string_view message) {
        messages.emplace_back(message);
    });
    request_.set_desturi("qemu+tls://user:secret@192.168.1.100/system");
    const auto reply = MigrateReply();
    Logger::Instance()->Reset();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 0);
    for (const auto &message : messages) {
        EXPECT_EQ(message.find("secret"), std::string::npos);
    }
}

TEST_F(SourceMigrationAdmissionTest, AcceptsDestinationIpv4WithExplicitPort)
{
    request_.set_desturi("qemu+tls://192.168.1.100:16509/system");
    std::string ipv4;
    ASSERT_TRUE(ParseMigrationDestinationUri(request_.desturi(), ipv4));
    EXPECT_EQ(ipv4, "192.168.1.100");
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK)) << reply.DebugString();
    EXPECT_EQ(State().admissionCalls, 1);
    EXPECT_EQ(State().startCalls, 1);
}

TEST_F(SourceMigrationAdmissionTest, DestinationUriParserRejectsUnsupportedAuthorityAndSuffixForms)
{
    for (const char *uri : {
             "qemu+ssh://192.168.1.100/system",
             "qemu+tls://user@192.168.1.100/system",
             "qemu+tls://192.168.001.100/system",
             "qemu+tls://192.168.1.100:0/system",
             "qemu+tls://192.168.1.100/session",
             "qemu+tls://192.168.1.100/system?x=1",
             "qemu+tls://192.168.1.100/system#fragment",
         }) {
        std::string ipv4 = "stale";
        EXPECT_FALSE(ParseMigrationDestinationUri(uri, ipv4)) << uri;
        EXPECT_TRUE(ipv4.empty()) << uri;
    }
}

TEST_F(SourceMigrationAdmissionTest, DomainQueryFailureFailsBeforeSessionAndReleasesAdmission)
{
    ScopedDomainListFailure failQuery;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, SourceConnectionFailureReleasesAdmissionWithoutSession)
{
    ScopedSourceConnectFailure failConnection;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().admissionCalls, 1);
    EXPECT_EQ(failConnection.Calls(), 1);
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, UnsafeAdmissionDirectoryIsErrorNotBusy)
{
    ASSERT_TRUE(std::filesystem::create_directory(State().directory));
    ASSERT_EQ(chmod(State().directory.c_str(), 0755), 0);
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(chmod(State().directory.c_str(), 0700), 0);
}

TEST_F(SourceMigrationAdmissionTest, HoldsExclusiveThroughStartAndCleanup)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->SetUri(request_.localuri()));
    ASSERT_TRUE(conn->Connect());
    std::unordered_map<std::string, DomainInfo> domains;
    ASSERT_EQ(DomainList(conn, LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE, domains, false), VirtrustRc::OK);
    ASSERT_EQ(domains.count(UUID), 1U);
    ASSERT_EQ(domains.at(UUID).domainName, request_.domainname());
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().startCalls, 1);
    EXPECT_TRUE(State().startSawExclusive);
    EXPECT_TRUE(State().cleanupSawExclusive);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, SuccessfulSourceSessionDiagnosticSurvivesUdsReply)
{
    State().useRealStart = true;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::OK));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_SUCCESS);
    EXPECT_FALSE(reply.diagnostic().has_primary_error());
    EXPECT_FALSE(reply.diagnostic().manual_check_required());
    EXPECT_NE(reply.diagnostic().confirmed_steps() &
                  static_cast<uint32_t>(MigrationStep::DestinationConfirmed), 0U);
    EXPECT_TRUE(State().cleanupSawExclusive);
}

TEST_F(SourceMigrationAdmissionTest, LocalSessionUriCanMigrateUnderExclusiveAdmission)
{
    request_.set_localuri("qemu:///session");
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::OK));
    EXPECT_EQ(State().startCalls, 1);
    EXPECT_TRUE(State().startSawExclusive);
    EXPECT_TRUE(State().cleanupSawExclusive);
}

TEST_F(SourceMigrationAdmissionTest, StartFailureReleasesAdmissionAndSession)
{
    State().startResult = MigrateSessionRc::ERROR;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_TRUE(State().cleanupSawExclusive);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, AcquireExceptionReturnsErrorWithoutSession)
{
    State().throwOnAcquire = true;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_UNKNOWN);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREFLIGHT);
    EXPECT_EQ(reply.diagnostic().primary_error().side(), protos::MIGRATION_SIDE_SOURCE);
    EXPECT_TRUE(reply.diagnostic().manual_check_required());
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, StartExceptionStillCleansSessionAndReleasesAdmission)
{
    State().throwOnStart = true;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_UNKNOWN);
    EXPECT_EQ(reply.diagnostic().primary_error().stage(), protos::MIGRATION_STAGE_PREPARE);
    EXPECT_EQ(reply.diagnostic().primary_error().side(), protos::MIGRATION_SIDE_SOURCE);
    EXPECT_TRUE(reply.diagnostic().manual_check_required());
    EXPECT_TRUE(State().cleanupSawExclusive);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, CleanupExceptionDoesNotLeaveSessionRegistered)
{
    State().throwOnCleanup = true;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_TRUE(State().cleanupSawExclusive);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}

TEST_F(SourceMigrationAdmissionTest, CleanupExceptionDoesNotRemoveReplacementSession)
{
    State().throwOnCleanup = true;
    State().replaceBeforeCleanupFailure = true;
    const auto reply = MigrateReply();
    EXPECT_EQ(reply.result(), static_cast<uint32_t>(VirtrustRc::ERROR));
    ASSERT_TRUE(reply.has_diagnostic());
    EXPECT_EQ(reply.diagnostic().outcome(), protos::MIGRATION_OUTCOME_UNKNOWN);
    auto replacement = State().replacement;
    ASSERT_NE(replacement, nullptr);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), replacement);
    State().throwOnCleanup = false;
    replacement->Cleanup();
    State().replacement.reset();
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
}
} // 匿名命名空间
} // 命名空间 virtrust

extern "C" virtrust::LockOutcome RealSourceAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__real__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedSourceAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__wrap__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedSourceAdmission(virtrust::NodeAdmission *self,
    virtrust::AdmissionKind kind, const std::string &directory, uid_t owner)
{
    if (directory != "/run/virtrust") {
        return RealSourceAdmission(self, kind, directory, owner);
    }
    auto &state = virtrust::State();
    ++state.admissionCalls;
    EXPECT_EQ(kind, virtrust::AdmissionKind::Migration);
    EXPECT_EQ(owner, 0U);
    if (state.throwOnAcquire) {
        throw std::bad_alloc();
    }
    return RealSourceAdmission(self, kind, state.directory, geteuid());
}

extern "C" virtrust::MigrateSessionRc RealSourceStart(virtrust::MigrationSession *)
    asm("__real__ZN8virtrust16MigrationSession5StartEv");
extern "C" virtrust::MigrateSessionRc WrappedSourceStart(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession5StartEv");
extern "C" virtrust::MigrateSessionRc WrappedSourceStart(virtrust::MigrationSession *session)
{
    auto &state = virtrust::State();
    ++state.startCalls;
    virtrust::NodeAdmission ordinary;
    state.startSawExclusive = ordinary.TryAcquire(virtrust::AdmissionKind::OrdinaryMutation,
                                                  state.directory, geteuid()) == virtrust::LockOutcome::Busy;
    if (state.throwOnStart) {
        throw std::runtime_error("Injected start failure");
    }
    if (state.useRealStart) {
        return RealSourceStart(session);
    }
    return state.startResult;
}

extern "C" void RealSourceCleanup(virtrust::MigrationSession *)
    asm("__real__ZN8virtrust16MigrationSession7CleanupEv");
extern "C" void WrappedSourceCleanup(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession7CleanupEv");
extern "C" void WrappedSourceCleanup(virtrust::MigrationSession *session)
{
    auto &state = virtrust::State();
    virtrust::NodeAdmission ordinary;
    state.cleanupSawExclusive = ordinary.TryAcquire(virtrust::AdmissionKind::OrdinaryMutation,
                                                    state.directory, geteuid()) == virtrust::LockOutcome::Busy;
    if (state.throwOnCleanup) {
        if (state.replaceBeforeCleanupFailure && state.replacement == nullptr) {
            // 模拟旧会话清理抛异常前，同 UUID 登记已被另一会话替换。
            auto &manager = virtrust::SessionManager::GetInstance();
            manager.RemoveSession(session->Id());
            state.replacement = manager.CreateSession(virtrust::MigrationSession::Role::Initiator,
                session->Id(), "replacement-domain", "", "", 0);
        }
        throw std::runtime_error("Injected cleanup failure");
    }
    RealSourceCleanup(session);
}
