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
} // 匿名命名空间

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
