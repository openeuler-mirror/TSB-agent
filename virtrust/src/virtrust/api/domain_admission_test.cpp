/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>

#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "virtrust/api/admission_test_support.h"
#include "virtrust/api/domain.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/base/custom_logger.h"
#include "virtrust/base/process_file_lock.h"

namespace virtrust {
namespace {
volatile sig_atomic_t signalCount = 0;
void CountSignal(int) { signalCount = 1; }

// 测试结束恢复进程信号处理器，信号处理器本身只写信号安全变量。
class SignalScope {
public:
    SignalScope()
    {
        struct sigaction action{};
        action.sa_handler = CountSignal;
        sigemptyset(&action.sa_mask);
        installed_ = sigaction(SIGUSR1, &action, &previous_) == 0;
    }
    ~SignalScope() { if (installed_) { sigaction(SIGUSR1, &previous_, nullptr); } }
    bool Installed() const { return installed_; }
private:
    struct sigaction previous_{};
    bool installed_ = false;
};

TEST(DomainAdmissionSupportTest, SignalInterruptedReadContinuesAndKeepsOriginalDeadline)
{
    SignalScope signal;
    ASSERT_TRUE(signal.Installed());
    for (bool deliverByte : {true, false}) {
        SCOPED_TRACE(deliverByte);
        signalCount = 0;
        int pipeFd[2];
        ASSERT_EQ(pipe2(pipeFd, O_CLOEXEC), 0);
        test::TestFd readEnd(pipeFd[0]);
        test::TestFd writeEnd(pipeFd[1]);
        const pid_t parent = getpid();
        const pid_t pid = fork();
        ASSERT_GE(pid, 0);
        if (pid == 0) {
            if (setpgid(0, 0) != 0) { _exit(1); }
            // 发送多次信号；无数据分支保持发送至父测试析构清理，检验期限不会重置。
            for (int i = 0; !deliverByte || i < 20; ++i) {
                kill(parent, SIGUSR1);
                usleep(1000);
            }
            const char token = 'R';
            _exit(write(writeEnd.Get(), &token, 1) == 1 ? 0 : 2);
        }
        test::TestChild child(pid);
        writeEnd.Reset();
        char token = '?';
        const auto start = std::chrono::steady_clock::now();
        EXPECT_EQ(test::ReadByteWithin(readEnd.Get(), token, std::chrono::milliseconds(100)), deliverByte);
        EXPECT_EQ(signalCount, 1);
        if (deliverByte) {
            EXPECT_EQ(token, 'R');
            EXPECT_TRUE(child.WaitSuccessful());
        } else {
            EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(1));
        }
    }
}

TEST(DomainAdmissionSupportTest, DescriptorIsClosedDuringExceptionUnwind)
{
    int descriptor = -1;
    try {
        test::TestFd fd(open("/dev/null", O_RDONLY | O_CLOEXEC));
        ASSERT_GE(fd.Get(), 0);
        descriptor = fd.Get();
        throw std::runtime_error("Injected scope exit");
    } catch (const std::runtime_error &) {
    }
    EXPECT_EQ(fcntl(descriptor, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

// 参数覆盖四个普通变更入口，以及三个独立的 only-tsb 分支。
class DomainAdmissionTest : public testing::TestWithParam<int> {
protected:
    void SetUp() override
    {
        auto &state = test::AdmissionState();
        state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
        state.productionPolicy = state.failLegacyOpen = state.throwInBusiness = false;
        state.acquireException = 0;
        conn_ = std::make_unique<ConnCtx>();
        ASSERT_TRUE(conn_->Connect());
    }
    void TearDown() override
    {
        Logger::Instance()->Reset();
        auto &state = test::AdmissionState();
        state.productionPolicy = state.failLegacyOpen = state.throwInBusiness = false;
        state.acquireException = 0;
    }
    VirtrustRc Invoke()
    {
        const std::string uuid = "12345678-1234-1234-1234-123456789002";
        switch (GetParam()) {
            case 0: return DomainCreate(conn_, {"/usr/bin/virt-install", "--name", "test-vm"});
            case 1: return DomainDestroy(conn_, "test-domain-1", 0, false);
            case 2: return DomainStart(conn_, "test-domain-1", 0, false);
            case 3: return DomainUndefine(conn_, "test-domain-1", 0, false);
            case 4: return DomainDestroy(conn_, uuid, 0, true);
            case 5: return DomainStart(conn_, uuid, 0, true);
            default: return DomainUndefine(conn_, uuid, 0, true);
        }
    }
    std::unique_ptr<ConnCtx> conn_;
};

TEST_P(DomainAdmissionTest, MigrationRejectsBeforeLegacyLockAndBusiness)
{
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, test::AdmissionState().directory, geteuid()),
              LockOutcome::Acquired);
    // 数值断言使测试可以先在未追加枚举值的旧实现上运行并失败。
    EXPECT_EQ(static_cast<unsigned>(Invoke()), 4U);
    EXPECT_EQ(test::AdmissionState().admissionCalls, 1);
    EXPECT_EQ(test::AdmissionState().legacyOpens, 0);
    EXPECT_EQ(test::AdmissionState().businessCalls, 0);
}

TEST(DomainMigrationAdmissionTest, SendsValidMigrationWithoutOpeningLegacyLock)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.legacyOpens = state.udsCalls = 0;
    state.failLegacyOpen = true;
    state.udsResultOverride = 0;
    EXPECT_EQ(DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system", MIGRATE_UNDEFINE_SOURCE).rc,
              VirtrustRc::OK);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.udsCalls, 1);
    state.failLegacyOpen = false;
    state.udsResultOverride = -999;
}

TEST(DomainMigrationAdmissionTest, RejectsRemoteSourceBeforeBusinessQueryOrUds)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->SetUri("qemu+ssh://remote.example.com/system"));
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.businessCalls = state.legacyOpens = state.udsCalls = 0;
    state.udsResultOverride = 0;
    EXPECT_EQ(DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system", MIGRATE_UNDEFINE_SOURCE).rc,
              VirtrustRc::ERROR);
    EXPECT_EQ(state.businessCalls, 0);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.udsCalls, 0);
    state.udsResultOverride = -999;
}

TEST(DomainMigrationAdmissionTest, RejectsDestinationHostnameBeforeUds)
{
    const auto conn = std::make_unique<ConnCtx>();
    auto &state = test::AdmissionState();
    state.udsCalls = 0;
    state.udsResultOverride = 0;
    const MigrationResult result = DomainMigrate(conn, "test-domain-2",
        "qemu+tls://remote.example.com/system?hint=192.168.1.100", MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(result.rc, VirtrustRc::ERROR);
    EXPECT_EQ(result.outcome, MigrationOutcome::FailedBeforeEffect);
    EXPECT_EQ(state.udsCalls, 0);
    state.udsResultOverride = -999;
}

TEST(DomainMigrationAdmissionTest, TsbListFailureKeepsPreflightOriginAndRawCode)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.getVRootsOverride = -71;
    state.udsCalls = 0;
    const auto result = DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system",
                                      MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(result.rc, VirtrustRc::ERROR);
    EXPECT_EQ(result.outcome, MigrationOutcome::FailedBeforeEffect);
    EXPECT_TRUE(result.hasPrimaryError);
    EXPECT_EQ(result.primaryError.stage, MigrationStage::Preflight);
    EXPECT_EQ(result.primaryError.operation, MigrationOperation::GetDescription);
    EXPECT_EQ(result.primaryError.origin, MigrationErrorOrigin::Tsb);
    EXPECT_TRUE(result.primaryError.hasRawCode);
    EXPECT_EQ(result.primaryError.rawCode, -71);
    EXPECT_EQ(state.udsCalls, 0);
    state.getVRootsOverride = 0;
}

TEST(DomainMigrationAdmissionTest, MalformedSuccessfulTsbOutputIsInternalWithoutRawCode)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    for (const int malformed : {1, 2}) {
        SCOPED_TRACE(malformed);
        state.malformedGetVRoots = malformed;
        state.udsCalls = 0;
        const auto result = DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system",
                                          MIGRATE_UNDEFINE_SOURCE);
        EXPECT_EQ(result.outcome, MigrationOutcome::FailedBeforeEffect);
        EXPECT_TRUE(result.hasPrimaryError);
        EXPECT_EQ(result.primaryError.operation, MigrationOperation::GetDescription);
        EXPECT_EQ(result.primaryError.origin, MigrationErrorOrigin::Internal);
        EXPECT_FALSE(result.primaryError.hasRawCode);
        EXPECT_EQ(state.udsCalls, 0);
    }
    state.malformedGetVRoots = 0;
}

TEST(DomainMigrationAdmissionTest, InvalidListArgumentsReportValidationCause)
{
    std::unordered_map<std::string, DomainInfo> domains;
    MigrationError failure;
    EXPECT_EQ(DomainList(nullptr, LIST_DOMAINS_ACTIVE, domains, false, &failure), VirtrustRc::ERROR);
    EXPECT_EQ(failure.operation, MigrationOperation::Validate);
    EXPECT_EQ(failure.origin, MigrationErrorOrigin::Validation);
    auto conn = std::make_unique<ConnCtx>();
    failure = {};
    EXPECT_EQ(DomainList(conn, 0, domains, false, &failure), VirtrustRc::ERROR);
    EXPECT_EQ(failure.operation, MigrationOperation::Validate);
    EXPECT_EQ(failure.origin, MigrationErrorOrigin::Validation);
}

TEST(DomainMigrationAdmissionTest, OnlyExplicitLocalSourceUrisAreAllowed)
{
    EXPECT_TRUE(IsLocalMigrationSourceUri("qemu:///system"));
    EXPECT_TRUE(IsLocalMigrationSourceUri("qemu:///session"));
    for (const auto uri : {"", "qemu+ssh://remote.example.com/system", "qemu+tls://remote.example.com/system",
                           "qemu:///system?socket=/tmp/libvirt.sock", "qemu:///system/"}) {
        EXPECT_FALSE(IsLocalMigrationSourceUri(uri)) << uri;
    }
}

TEST(DomainMigrationAdmissionTest, MapsDaemonBusyButOtherFailuresRemainErrors)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.legacyOpens = state.udsCalls = 0;
    for (const auto &[reply, expected] : {
             std::pair<int, VirtrustRc>{4, VirtrustRc::BUSY},
             {1, VirtrustRc::ERROR},
             {-1, VirtrustRc::ERROR}}) {
        state.udsResultOverride = reply;
        const auto result = DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system",
                                          MIGRATE_UNDEFINE_SOURCE);
        EXPECT_EQ(result.rc, expected);
        if (expected == VirtrustRc::BUSY) {
            EXPECT_EQ(result.outcome, MigrationOutcome::FailedBeforeEffect);
            EXPECT_FALSE(result.manualCheckRequired);
        }
    }
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.udsCalls, 3);
    state.udsResultOverride = -999;
}

TEST(DomainMigrationAdmissionTest, BusySurvivesDiagnosticFailure)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.udsResultOverride = static_cast<int>(VirtrustRc::BUSY);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::ERROR) {
            throw std::bad_alloc();
        }
    });
    EXPECT_EQ(DomainMigrate(conn, "test-domain-2", "qemu+tls://192.168.1.100/system", MIGRATE_UNDEFINE_SOURCE).rc,
              VirtrustRc::BUSY);
    Logger::Instance()->Reset();
    state.udsResultOverride = -999;
}

TEST_P(DomainAdmissionTest, SharedAdmissionAllowsBusinessAndReleasesOnReturn)
{
    NodeAdmission ordinary;
    auto &state = test::AdmissionState();
    ASSERT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, state.directory, geteuid()), LockOutcome::Acquired);
    EXPECT_NE(static_cast<unsigned>(Invoke()), 4U);
    EXPECT_EQ(state.admissionCalls, 1);
    EXPECT_EQ(state.legacyOpens, 1);
    EXPECT_GT(state.businessCalls, 0);
    ordinary.Release();
    NodeAdmission migration;
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
}

TEST_P(DomainAdmissionTest, BadDirectoryIsErrorWithoutBusiness)
{
    auto &state = test::AdmissionState();
    std::filesystem::create_directory(state.directory);
    ASSERT_EQ(chmod(state.directory.c_str(), 0755), 0);
    const auto rc = Invoke();
    EXPECT_EQ(chmod(state.directory.c_str(), 0700), 0);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_EQ(state.admissionCalls, 1);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

TEST_P(DomainAdmissionTest, AcquisitionExceptionsAreErrors)
{
    auto &state = test::AdmissionState();
    for (int kind : {1, 2}) {
        state.acquireException = kind;
        EXPECT_EQ(Invoke(), VirtrustRc::ERROR);
    }
    EXPECT_EQ(state.admissionCalls, 2);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

TEST_P(DomainAdmissionTest, BusySurvivesDiagnosticFailure)
{
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, test::AdmissionState().directory, geteuid()),
              LockOutcome::Acquired);
    Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
        if (level == LogLevel::ERROR) {
            throw std::bad_alloc();
        }
    });
    EXPECT_EQ(static_cast<unsigned>(Invoke()), 4U);
    EXPECT_EQ(test::AdmissionState().businessCalls, 0);
}

TEST_P(DomainAdmissionTest, LegacyLockFailureReleasesAdmission)
{
    auto &state = test::AdmissionState();
    state.failLegacyOpen = true;
    EXPECT_EQ(Invoke(), VirtrustRc::ERROR);
    EXPECT_EQ(state.legacyOpens, 1);
    EXPECT_EQ(state.businessCalls, 0);
    NodeAdmission migration;
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
}

TEST_P(DomainAdmissionTest, ProductionPolicyRejectsNonRoot)
{
    if (geteuid() == 0) {
        GTEST_SKIP() << "This test verifies the non-root production caller";
    }
    auto &state = test::AdmissionState();
    state.productionPolicy = true;
    EXPECT_EQ(Invoke(), VirtrustRc::ERROR);
    EXPECT_EQ(state.admissionCalls, 1);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

INSTANTIATE_TEST_SUITE_P(OrdinaryEntrypoints, DomainAdmissionTest, testing::Range(0, 7));

TEST(DomainAdmissionValidationTest, InvalidOrdinaryArgumentsPrecedeBusy)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);

    for (int scenario = 0; scenario < 7; ++scenario) {
        SCOPED_TRACE(scenario);
        state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
        VirtrustRc rc = VirtrustRc::OK;
        switch (scenario) {
            case 0: rc = DomainDestroy(conn, "test-domain", 123, false); break;
            case 1: rc = DomainDestroy(conn, "short-uuid", 123, true); break;
            case 2: rc = DomainStart(conn, "test-domain", 123, false); break;
            case 3: rc = DomainStart(conn, "short-uuid", 123, true); break;
            case 4: rc = DomainUndefine(conn, "", 0, false); break;
            case 5: rc = DomainUndefine(conn, "test-domain", 123, false); break;
            case 6: rc = DomainUndefine(conn, "short-uuid", 123, true); break;
        }
        EXPECT_EQ(rc, VirtrustRc::ERROR);
        EXPECT_EQ(state.admissionCalls, 0);
        EXPECT_EQ(state.legacyOpens, 0);
        EXPECT_EQ(state.businessCalls, 0);
    }
}

TEST(DomainAdmissionValidationTest, NullStartConnectionFailsBeforeAdmissionEvenWhenNodeIsBusy)
{
    const std::unique_ptr<ConnCtx> emptyConn;
    auto &state = test::AdmissionState();
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);

    EXPECT_EQ(DomainStart(emptyConn, "test-domain-1", DOMAIN_START_NONE, false), VirtrustRc::ERROR);
    EXPECT_EQ(state.admissionCalls, 0);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

TEST(DomainAdmissionValidationTest, InvalidCreateArgumentsPrecedeBusyWithoutChangingConnection)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    const auto originalUri = conn->GetUri();
    auto &state = test::AdmissionState();
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);

    const std::vector<std::vector<std::string>> invalidArgs = {
        {"/usr/bin/virt-install", "--connect=qemu:///other"},
        {"/usr/bin/virt-install", "--name", std::string(201, 'x')},
        {"/usr/bin/virt-install", "--name", "test-vm", "--allow-store-measurements=true"},
    };
    for (size_t scenario = 0; scenario < invalidArgs.size(); ++scenario) {
        SCOPED_TRACE(scenario);
        state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
        EXPECT_EQ(DomainCreate(conn, invalidArgs[scenario]), VirtrustRc::ERROR);
        EXPECT_EQ(conn->GetUri(), originalUri);
        EXPECT_EQ(state.admissionCalls, 0);
        EXPECT_EQ(state.legacyOpens, 0);
        EXPECT_EQ(state.businessCalls, 0);
    }
}

TEST(DomainAdmissionValidationTest, OnlyTsbNonzeroFlagsRemainEligibleForAdmission)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
    const std::string uuid = "12345678-1234-1234-1234-123456789002";

    for (int scenario = 0; scenario < 3; ++scenario) {
        SCOPED_TRACE(scenario);
        state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
        VirtrustRc rc = VirtrustRc::ERROR;
        switch (scenario) {
            case 0: rc = DomainDestroy(conn, uuid, 123, true); break;
            case 1: rc = DomainStart(conn, uuid, 123, true); break;
            case 2: rc = DomainUndefine(conn, uuid, 123, true); break;
        }
        EXPECT_EQ(rc, VirtrustRc::BUSY);
        EXPECT_EQ(state.admissionCalls, 1);
        EXPECT_EQ(state.legacyOpens, 0);
        EXPECT_EQ(state.businessCalls, 0);
    }
}

TEST(DomainAdmissionValidationTest, OnlyTsbNonzeroFlagsPreserveBusinessResults)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    const std::string stoppedUuid = "12345678-1234-1234-1234-123456789002";
    const std::string runningUuid = "12345678-1234-1234-1234-123456789003";
    const std::string absentUuid = "12345678-1234-1234-1234-123456789999";
    // 启动、停止、删除分别验证成功与业务失败；非零 flags 均不改变 only-tsb 旧契约。
    for (int operation = 0; operation < 3; ++operation) {
        for (bool success : {true, false}) {
            SCOPED_TRACE(operation);
            SCOPED_TRACE(success);
            state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
            VirtrustRc rc = VirtrustRc::ERROR;
            if (operation == 0) {
                rc = DomainStart(conn, success ? stoppedUuid : absentUuid, 666, true);
            } else if (operation == 1) {
                rc = DomainDestroy(conn, success ? runningUuid : stoppedUuid, 666, true);
            } else {
                rc = DomainUndefine(conn, success ? stoppedUuid : runningUuid, 666, true);
            }
            EXPECT_EQ(rc, success ? VirtrustRc::OK : VirtrustRc::ERROR);
            EXPECT_EQ(state.admissionCalls, 1);
            EXPECT_EQ(state.legacyOpens, 1);
            EXPECT_GT(state.businessCalls, 0);
        }
    }
}

TEST(DomainAdmissionProductionPathTest, RootUsesLiteralRuntimeDirectory)
{
    // 仅在独立挂载命名空间中显式启用，避免常规 CI 触碰宿主 /run/virtrust。
    const char *enabled = std::getenv("VIRTRUST_TASK4_LITERAL_ROOT");
    if (geteuid() != 0 || enabled == nullptr || std::strcmp(enabled, "1") != 0) {
        GTEST_SKIP() << "Requires root and an isolated /run mount namespace";
    }
    ASSERT_TRUE(std::filesystem::exists("/run/.virtrust-task4-isolated"));
    ASSERT_FALSE(std::filesystem::exists("/run/virtrust"));
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
    state.productionPolicy = true;
    const std::string uuid = "12345678-1234-1234-1234-123456789002";
    const auto first = DomainStart(conn, uuid, 0, true);
    NodeAdmission migration;
    const auto exclusive = migration.TryAcquire(AdmissionKind::Migration);
    const auto busy = DomainStart(conn, uuid, 0, true);
    migration.Release();
    state.productionPolicy = false;

    struct stat directory {}, lockFile {};
    EXPECT_EQ(first, VirtrustRc::OK);
    EXPECT_EQ(exclusive, LockOutcome::Acquired);
    EXPECT_EQ(busy, VirtrustRc::BUSY);
    EXPECT_EQ(stat("/run/virtrust", &directory), 0);
    EXPECT_EQ(stat("/run/virtrust/node-admission.lock", &lockFile), 0);
    EXPECT_EQ(directory.st_uid, 0U);
    EXPECT_EQ(directory.st_mode & 0777, 0700U);
    EXPECT_EQ(lockFile.st_uid, 0U);
    EXPECT_EQ(lockFile.st_mode & 0777, 0600U);
    EXPECT_EQ(state.admissionCalls, 2);
    EXPECT_EQ(state.legacyOpens, 1);
    EXPECT_GT(state.businessCalls, 0);
}

TEST(DomainAdmissionValidationTest, DisconnectedCreateConnectionFailsBeforeAdmission)
{
    auto conn = std::make_unique<ConnCtx>();
    auto &state = test::AdmissionState();
    state.admissionCalls = state.legacyOpens = state.businessCalls = 0;

    EXPECT_EQ(DomainCreate(conn, {"/usr/bin/virt-install", "--name", "test-vm"}), VirtrustRc::ERROR);
    EXPECT_EQ(state.admissionCalls, 0);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

TEST(DomainAdmissionValidationTest, MismatchedCreateConnectionFailsBeforeAdmission)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    auto &state = test::AdmissionState();
    state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
    state.observedConnection = conn.get();
    state.expectedUriBeforePreparation = conn->GetUri();

    EXPECT_EQ(DomainCreate(conn, {"/usr/bin/virt-install", "--name", "test-vm", "--connect=qemu:///other"}),
              VirtrustRc::ERROR);

    EXPECT_EQ(conn->GetUri(), state.expectedUriBeforePreparation);
    EXPECT_EQ(state.admissionCalls, 0);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

TEST(DomainAdmissionValidationTest, ValidCreateConnectOptionDoesNotChangeConnectionWhenBusy)
{
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    const auto originalUri = conn->GetUri();
    auto &state = test::AdmissionState();
    NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(DomainCreate(conn, {"/usr/bin/virt-install", "--name", "test-vm", "--connect=" + originalUri}),
        VirtrustRc::BUSY);
    EXPECT_EQ(conn->GetUri(), originalUri);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}

// 只用于测试前置同步：确认子进程确实在等待某个 FLOCK。
bool WaitForAnyFlock(pid_t pid, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream locks("/proc/locks");
        std::string line;
        while (std::getline(locks, line)) {
            std::istringstream fields(line);
            std::string id, arrow, kind, advisory, mode;
            pid_t owner = -1;
            if (fields >> id >> arrow >> kind >> advisory >> mode >> owner && arrow == "->" && kind == "FLOCK" &&
                owner == pid) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

// 测试进程通过 /proc/locks 观察子进程已经阻塞于真实旧锁，而非仅推测时序。
bool WaitForLegacyFlock(pid_t pid, std::chrono::milliseconds timeout = std::chrono::seconds(3))
{
    struct stat target {};
    if (stat(test::AdmissionState().legacyPath.c_str(), &target) != 0) {
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream locks("/proc/locks");
        std::string line;
        while (std::getline(locks, line)) {
            std::istringstream fields(line);
            std::string id, arrow, kind, advisory, mode, fileIdentity;
            pid_t owner = -1;
            if (!(fields >> id >> arrow >> kind >> advisory >> mode >> owner >> fileIdentity) || arrow != "->" ||
                kind != "FLOCK" || owner != pid) {
                continue;
            }
            unsigned int deviceMajor = 0, deviceMinor = 0;
            unsigned long long inode = 0;
            char firstSeparator = 0, secondSeparator = 0;
            std::istringstream identity(fileIdentity);
            if (!(identity >> std::hex >> deviceMajor >> firstSeparator >> deviceMinor >> secondSeparator >>
                  std::dec >> inode) || firstSeparator != ':' || secondSeparator != ':') {
                continue;
            }
            if (deviceMajor == major(target.st_dev) && deviceMinor == minor(target.st_dev) &&
                inode == target.st_ino) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}


TEST(DomainAdmissionOrderingTest, LegacyProbeRejectsUnrelatedFlockFromSameChild)
{
    auto &state = test::AdmissionState();
    ProcessFileLock legacy;
    ProcessFileLock unrelated;
    ASSERT_EQ(legacy.Acquire(state.legacyPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    ASSERT_EQ(unrelated.Acquire(state.legacyPath + ".unrelated", LockMode::Exclusive, LockWait::Try),
        LockOutcome::Acquired);
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        if (setpgid(0, 0) != 0) { _exit(3); }
        legacy.Release();
        unrelated.Release();
        ProcessFileLock waiter;
        _exit(waiter.Acquire(state.legacyPath + ".unrelated", LockMode::Exclusive, LockWait::Block) ==
                      LockOutcome::Acquired ? 0 : 2);
    }
    test::TestChild child(pid);
    const bool waitingElsewhere = WaitForAnyFlock(pid, std::chrono::seconds(3));
    const bool mistakenForLegacy = WaitForLegacyFlock(pid, std::chrono::milliseconds(100));
    unrelated.Release();
    legacy.Release();
    ASSERT_TRUE(child.WaitSuccessful());
    ASSERT_TRUE(waitingElsewhere);
    EXPECT_FALSE(mistakenForLegacy);
}

TEST(DomainAdmissionOrderingTest, WaitingOrdinaryRequestRetainsSharedQualification)
{
    auto &state = test::AdmissionState();
    ProcessFileLock legacy;
    ASSERT_EQ(legacy.Acquire(state.legacyPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    int resultPipe[2]{-1, -1};
    ASSERT_EQ(pipe(resultPipe), 0);
    test::TestFd resultRead(resultPipe[0]);
    test::TestFd resultWrite(resultPipe[1]);
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        if (setpgid(0, 0) != 0) { _exit(3); }
        close(resultPipe[0]);
        // 父子继承同一打开文件对象：只关闭子进程副本，不解除父进程旧锁。
        legacy.Release();
        auto conn = std::make_unique<ConnCtx>();
        if (conn->Connect()) {
            const auto rc = DomainStart(conn, "12345678-1234-1234-1234-123456789002", 0, true);
            const char code = rc == VirtrustRc::OK ? 'S' : 'F';
            const auto written = write(resultPipe[1], &code, 1);
            if (written != 1) {
                _exit(2);
            }
        }
        close(resultPipe[1]);
        _exit(testing::Test::HasFailure() ? 4 : 0);
    }
    test::TestChild child(pid);
    resultWrite.Reset();
    const bool waiting = WaitForLegacyFlock(pid);
    // 无论断言结果如何，先释放父进程的旧锁，保证子进程能在限定时间内结束。
    NodeAdmission migration;
    const auto migrationRc = migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid());
    legacy.Release();
    char childResult = 0;
    const bool received = test::ReadByteWithin(resultRead.Get(), childResult);
    ASSERT_TRUE(child.WaitSuccessful());
    ASSERT_TRUE(waiting);
    EXPECT_EQ(migrationRc, LockOutcome::Busy);
    EXPECT_TRUE(received);
    EXPECT_EQ(childResult, 'S');
}

TEST(DomainAdmissionOrderingTest, CreateConnectionStaysUnchangedBeforeLegacyLockIsAcquired)
{
    auto &state = test::AdmissionState();
    ProcessFileLock legacy;
    ASSERT_EQ(legacy.Acquire(state.legacyPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        if (setpgid(0, 0) != 0) { _exit(1); }
        legacy.Release();
        auto conn = std::make_unique<ConnCtx>();
        if (!conn->Connect()) { _exit(2); }
        state.observedConnection = conn.get();
        state.expectedUriBeforePreparation = conn->GetUri();
        (void)DomainCreate(conn, {"/usr/bin/virt-install", "--name", "test-vm", "--connect=" + conn->GetUri()});
        _exit(!testing::Test::HasFailure() && conn->GetUri() == state.expectedUriBeforePreparation ? 0 : 3);
    }
    test::TestChild child(pid);
    const bool waiting = WaitForLegacyFlock(pid);
    // open 包装检查锁前 URI，GetVRoots 包装再次检查锁内数量检查时的 URI。
    legacy.Release();
    EXPECT_TRUE(child.WaitSuccessful());
    EXPECT_TRUE(waiting);
}

TEST(DomainAdmissionLifetimeTest, BusinessExceptionUnwindsAdmission)
{
    auto &state = test::AdmissionState();
    state.admissionCalls = state.businessCalls = 0;
    auto conn = std::make_unique<ConnCtx>();
    ASSERT_TRUE(conn->Connect());
    state.throwInBusiness = true;
    EXPECT_THROW((void)DomainStart(conn, "12345678-1234-1234-1234-123456789002", 0, true), std::runtime_error);
    state.throwInBusiness = false;
    EXPECT_EQ(state.admissionCalls, 1);
    EXPECT_EQ(state.businessCalls, 1);
    NodeAdmission migration;
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
}
} // 匿名命名空间
} // 命名空间 virtrust
