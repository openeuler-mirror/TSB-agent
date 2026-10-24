/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "gtest/gtest.h"
#include <unistd.h>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_migration_result.h"

namespace virtrust {
namespace {

TEST(OpMigrationResultTest, CommandIsRegistered)
{
    EXPECT_EQ(OpTyFromStr("migration-result"), OpTy::MIGRATION_RESULT);
    EXPECT_NE(MakeOperator("migration-result"), nullptr);
}

TEST(OpMigrationResultTest, AcceptsOnlyCanonicalIdentityAndDestination)
{
    OpMigrationResult operation;
    const char *valid[] = {"migration-result", "12345678-1234-1234-1234-123456789001",
                           "qemu+tls://192.168.1.100/system", "0123456789abcdef0123456789abcdef"};
    EXPECT_EQ(operation.ParseArgv(4, const_cast<char **>(valid)), OpRc::OK);

    const char *badAttempt[] = {"migration-result", "12345678-1234-1234-1234-123456789001",
                                "qemu+tls://192.168.1.100/system", "bad\nvalue"};
    EXPECT_EQ(operation.ParseArgv(4, const_cast<char **>(badAttempt)), OpRc::ERROR);

    const char *badDestination[] = {"migration-result", "12345678-1234-1234-1234-123456789001",
                                    "qemu+ssh://192.168.1.100/system", "0123456789abcdef0123456789abcdef"};
    EXPECT_EQ(operation.ParseArgv(4, const_cast<char **>(badDestination)), OpRc::ERROR);

    const char *badUuid[] = {"migration-result", "bad", "qemu+tls://192.168.1.100/system",
                             "0123456789abcdef0123456789abcdef"};
    EXPECT_EQ(operation.ParseArgv(4, const_cast<char **>(badUuid)), OpRc::ERROR);
}

TEST(OpMigrationResultTest, NonRootCannotOpenQuery)
{
    if (geteuid() == 0) {
        GTEST_SKIP() << "The non-root permission branch needs a non-root test process";
    }
    OpMigrationResult operation;
    const char *args[] = {"migration-result", "12345678-1234-1234-1234-123456789001",
                          "qemu+tls://192.168.1.100/system", "0123456789abcdef0123456789abcdef"};
    ASSERT_EQ(operation.ParseArgv(4, const_cast<char **>(args)), OpRc::OK);
    testing::internal::CaptureStderr();
    const auto rc = operation.Exec();
    const auto message = testing::internal::GetCapturedStderr();
    EXPECT_EQ(rc, OpRc::ERROR);
    EXPECT_NE(message.find("requires root"), std::string::npos);
}

} // namespace
} // namespace virtrust
