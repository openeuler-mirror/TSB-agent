/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unordered_map>

#include "virtrust/api/domain.h"
#include "virtrust/api/defines.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/migration_service_impl.h"
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
        request_.set_flags(MIGRATE_UNDEFINE_SOURCE);
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
        protos::DomainMigraterReply reply;
        const auto status = service_.DomainMigrate(nullptr, &request_, &reply);
        EXPECT_TRUE(status.ok());
        return reply.result();
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
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::BUSY));
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
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(request_.uuid()), nullptr);
    NodeAdmission ordinary;
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, State().directory, geteuid()),
              LockOutcome::Acquired);
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
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
    EXPECT_EQ(State().startCalls, 0);
    EXPECT_EQ(SessionManager::GetInstance().GetSession(UUID), nullptr);
}

TEST_F(SourceMigrationAdmissionTest, StartExceptionStillCleansSessionAndReleasesAdmission)
{
    State().throwOnStart = true;
    EXPECT_EQ(Migrate(), static_cast<uint32_t>(VirtrustRc::ERROR));
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

extern "C" virtrust::MigrateSessionRc WrappedSourceStart(virtrust::MigrationSession *)
    asm("__wrap__ZN8virtrust16MigrationSession5StartEv");
extern "C" virtrust::MigrateSessionRc WrappedSourceStart(virtrust::MigrationSession *)
{
    auto &state = virtrust::State();
    ++state.startCalls;
    virtrust::NodeAdmission ordinary;
    state.startSawExclusive = ordinary.TryAcquire(virtrust::AdmissionKind::OrdinaryMutation,
                                                  state.directory, geteuid()) == virtrust::LockOutcome::Busy;
    if (state.throwOnStart) {
        throw std::runtime_error("Injected start failure");
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
        throw std::runtime_error("Injected cleanup failure");
    }
    RealSourceCleanup(session);
}
