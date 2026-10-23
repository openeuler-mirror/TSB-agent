/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include <stdexcept>
#include <string_view>
#include <utility>

#include "virtrust-sh/operator/op_migrate.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/migration_result.h"

namespace virtrust {
namespace {
// 异常或断言提前结束时恢复全局 libvirt 入口，避免污染后续用例。
class ScopedMigrationConnectFailure {
public:
    ScopedMigrationConnectFailure() : original_(Libvirt::GetInstance().virConnectOpen)
    {
        calls_ = 0;
        Libvirt::GetInstance().virConnectOpen = DlFun<virConnectPtr, const char *>(
            "virConnectOpen", +[](const char *) -> virConnectPtr {
                ++calls_;
                return nullptr;
            });
    }
    ~ScopedMigrationConnectFailure() { Libvirt::GetInstance().virConnectOpen = std::move(original_); }
    ScopedMigrationConnectFailure(const ScopedMigrationConnectFailure &) = delete;
    ScopedMigrationConnectFailure &operator=(const ScopedMigrationConnectFailure &) = delete;
    int Calls() const { return calls_; }

private:
    inline static int calls_ = 0;
    DlFun<virConnectPtr, const char *> original_;
};

// 故障注入退出时恢复日志回调，不把异常测试的配置带入后续用例。
class ScopedMigrationLoggerReset {
public:
    ~ScopedMigrationLoggerReset() { Logger::Instance()->Reset(); }
};

bool &InjectMigrationResult()
{
    static bool enabled = false;
    return enabled;
}

bool &InjectUnknownMigrationResult()
{
    static bool enabled = false;
    return enabled;
}

int &MigrationCallCount()
{
    static int count = 0;
    return count;
}

struct ScopedMigrationResultInjection {
    explicit ScopedMigrationResultInjection(bool unknown = false)
    {
        InjectMigrationResult() = true;
        InjectUnknownMigrationResult() = unknown;
        MigrationCallCount() = 0;
    }
    ~ScopedMigrationResultInjection()
    {
        InjectMigrationResult() = false;
        InjectUnknownMigrationResult() = false;
    }
};
} // 匿名命名空间

TEST(OpMigrateTest, PartialFailureShowsStageAndManualCheckWithoutRetry)
{
    ScopedMigrationResultInjection injection;
    OpMigrate operation;
    OpConfig config;
    config.uri = "qemu:///system";
    operation.SetConfig(config);
    const char *args[] = {"migrate", "test-domain-2", "qemu+tls://192.168.1.100/system"};
    ASSERT_EQ(operation.ParseArgv(3, const_cast<char **>(args)), OpRc::OK);

    testing::internal::CaptureStderr();
    const auto rc = operation.Exec();
    const std::string output = testing::internal::GetCapturedStderr();
    EXPECT_EQ(rc, OpRc::ERROR);
    EXPECT_EQ(MigrationCallCount(), 1);
    EXPECT_NE(output.find("PARTIAL"), std::string::npos);
    EXPECT_NE(output.find("SOURCE_CLEANUP"), std::string::npos);
    EXPECT_NE(output.find("raw_code=7"), std::string::npos);
    EXPECT_NE(output.find("Manual verification required"), std::string::npos);
    EXPECT_EQ(output.find("cipher"), std::string::npos);
}

TEST(OpMigrateTest, UnknownFailureShowsManualCheckWithoutInventingRawCode)
{
    ScopedMigrationResultInjection injection(true);
    OpMigrate operation;
    OpConfig config;
    config.uri = "qemu:///system";
    operation.SetConfig(config);
    const char *args[] = {"migrate", "test-domain-2", "qemu+tls://192.168.1.100/system"};
    ASSERT_EQ(operation.ParseArgv(3, const_cast<char **>(args)), OpRc::OK);

    testing::internal::CaptureStderr();
    const auto rc = operation.Exec();
    const std::string output = testing::internal::GetCapturedStderr();
    EXPECT_EQ(rc, OpRc::ERROR);
    EXPECT_EQ(MigrationCallCount(), 1);
    EXPECT_NE(output.find("UNKNOWN"), std::string::npos);
    EXPECT_NE(output.find("stage=UDS"), std::string::npos);
    EXPECT_NE(output.find("Manual verification required"), std::string::npos);
    EXPECT_EQ(output.find("raw_code="), std::string::npos);
}

TEST(OpMigrateTest, RejectsRemoteSourceBeforeConnecting)
{
    ScopedMigrationConnectFailure connection;

    OpMigrate opMigrate;
    OpConfig config;
    config.uri = "qemu+ssh://remote.example.com/system";
    opMigrate.SetConfig(config);
    const auto result = opMigrate.Exec();

    EXPECT_EQ(result, OpRc::ERROR);
    EXPECT_EQ(connection.Calls(), 0);
}

TEST(OpMigrateTest, RestoresConnectionHookAfterDiagnosticException)
{
    {
        ScopedMigrationConnectFailure connection;
        ScopedMigrationLoggerReset loggerReset;
        Logger::Instance()->SetCustomLogFunction([](LogLevel level, std::string_view) {
            if (level == LogLevel::ERROR) {
                throw std::runtime_error("Injected log failure");
            }
        });
        OpMigrate opMigrate;
        OpConfig config;
        config.uri = "qemu+ssh://remote.example.com/system";
        opMigrate.SetConfig(config);
        EXPECT_THROW(opMigrate.Exec(), std::runtime_error);
        EXPECT_EQ(connection.Calls(), 0);
    }

    ConnCtx conn;
    EXPECT_TRUE(conn.Connect());
}

TEST(OpMigrateTest, ParseArgvValidArgumentsTest)
{
    OpMigrate opMigrate;

    // Test with valid domain name and destination URI
    const char *argv[] = {"op_migrate", "test_doamin", "qemu+ssh://destination.example.com/system"};
    int argc = 3;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for valid arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpMigrateTest, ParseArgvHelpFlagTest)
{
    OpMigrate opMigrate;

    // Test with help Flag
    const char *argv[] = {"op_migrate", "--help"};
    int argc = 2;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpMigrateTest, ParseArgvHelpShortFlagTest)
{
    OpMigrate opMigrate;

    // Test with help Flag
    const char *argv[] = {"op_migrate", "-h"};
    int argc = 2;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for short help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpMigrateTest, ParseArgvMissingArgumentsTest)
{
    OpMigrate opMigrate;

    // Test with missig arguments (only program name)
    const char *argv[] = {"op_migrate"};
    int argc = 1;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for misssing arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpMigrateTest, ParseArgvMissingDestinationTest)
{
    OpMigrate opMigrate;

    // Test with aonly domain name, missing destination URI
    const char *argv[] = {"op_migrate", "test_domain"};
    int argc = 2;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for missing destination
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpMigrateTest, ParseArgvExtraArgumentsTest)
{
    OpMigrate opMigrate;

    // Test with extra arguments
    const char *argv[] = {"op_migrate", "domain1", "dest_uri", "extra_arg"};
    int argc = 4;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv return ERROR for extra arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpMigrateTest, ParseArgvInvalidOptionTest)
{
    OpMigrate opMigrate;

    // Test with invalid option
    const char *argv[] = {"op_migrate", "--invalid-option"};
    int argc = 2;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for invalid option
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpMigrateTest, ParseArgvComplexArgumentsTest)
{
    OpMigrate opMigrate;

    // Test with complex domain name and URI
    const char *argv[] = {"op_migrate", "complex-domain-name-123", "qemu+ssh://user@host:22/system?param=value"};
    int argc = 3;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for complex arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpMigrateTest, ParseArgvFlagCombinationTest)
{
    OpMigrate opMigrate;

    // Test with special characters in arguments
    const char *argv[] = {"op_migrate", "test-dimain_123", "qemu+ssh://user@host.example.com:22/system"};
    int argc = 3;

    OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for special characters
    EXPECT_EQ(result, OpRc::OK);
}
} // namespace virtrust

extern "C" virtrust::MigrationResult RealCliDomainMigrate(const std::unique_ptr<virtrust::ConnCtx> &,
    const std::string &, const std::string &, unsigned int)
    asm("__real__ZN8virtrust13DomainMigrateERKSt10unique_ptrINS_7ConnCtxESt14default_deleteIS1_EERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESE_j");
extern "C" virtrust::MigrationResult WrappedCliDomainMigrate(const std::unique_ptr<virtrust::ConnCtx> &,
    const std::string &, const std::string &, unsigned int)
    asm("__wrap__ZN8virtrust13DomainMigrateERKSt10unique_ptrINS_7ConnCtxESt14default_deleteIS1_EERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESE_j");
extern "C" virtrust::MigrationResult WrappedCliDomainMigrate(const std::unique_ptr<virtrust::ConnCtx> &connection,
    const std::string &name, const std::string &destination, unsigned int flags)
{
    if (!virtrust::InjectMigrationResult()) {
        return RealCliDomainMigrate(connection, name, destination, flags);
    }
    ++virtrust::MigrationCallCount();
    virtrust::MigrationResult result;
    if (virtrust::InjectUnknownMigrationResult()) {
        result.primaryError = {virtrust::MigrationStage::Uds, virtrust::MigrationSide::Source,
                               virtrust::MigrationOperation::NotifyPeer, virtrust::MigrationErrorOrigin::Grpc,
                               false, 0};
        result.hasPrimaryError = true;
        return result;
    }
    result.outcome = virtrust::MigrationOutcome::Partial;
    result.primaryError = {virtrust::MigrationStage::SourceCleanup, virtrust::MigrationSide::Source,
                           virtrust::MigrationOperation::RemoveVRoot, virtrust::MigrationErrorOrigin::Tsb,
                           true, 7};
    result.hasPrimaryError = true;
    result.manualCheckRequired = true;
    return result;
}
