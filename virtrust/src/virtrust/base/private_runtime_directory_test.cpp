/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>

#include "virtrust/base/private_runtime_directory.h"

namespace virtrust {
class PrivateRuntimeDirectoryTest : public testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-private-dir-ut.XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        root_ = created;
    }
    void TearDown() override
    {
        if (!root_.empty()) {
            std::filesystem::remove_all(root_);
        }
    }
    std::string root_;
};

TEST_F(PrivateRuntimeDirectoryTest, CreatesAndReusesPrivateDirectory)
{
    const auto path = root_ + "/run";
    RuntimeDirectoryError error;
    ASSERT_TRUE(EnsurePrivateRuntimeDirectory(path, geteuid(), error)) << error.step;
    struct stat info {};
    ASSERT_EQ(stat(path.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 07777, 0700u);
    EXPECT_TRUE(EnsurePrivateRuntimeDirectory(path, geteuid(), error));
    EXPECT_EQ(error.code, 0);
    EXPECT_TRUE(error.path.empty());
    EXPECT_TRUE(error.step.empty());
}

TEST_F(PrivateRuntimeDirectoryTest, RejectsUnsafeDirectoryWithoutChangingIt)
{
    const auto path = root_ + "/run";
    ASSERT_EQ(mkdir(path.c_str(), 0755), 0);
    // mkdir 的模式受外部 umask 影响，显式构造不安全权限；仅操作本用例自有目录。
    ASSERT_EQ(chmod(path.c_str(), 0755), 0);
    RuntimeDirectoryError error;
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory(path, geteuid(), error));
    EXPECT_EQ(error.code, EACCES);
    EXPECT_EQ(error.path, path);
    struct stat info {};
    ASSERT_EQ(stat(path.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 07777, 0755u);
}

TEST_F(PrivateRuntimeDirectoryTest, RejectsSymlinkAndMissingParent)
{
    RuntimeDirectoryError error;
    const auto link = root_ + "/link";
    ASSERT_EQ(symlink(root_.c_str(), link.c_str()), 0);
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory(link + "/run", geteuid(), error));
    EXPECT_EQ(error.path, link);
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory(root_ + "/missing/run", geteuid(), error));
    EXPECT_EQ(error.code, ENOENT);
    EXPECT_FALSE(std::filesystem::exists(root_ + "/missing"));
}

TEST_F(PrivateRuntimeDirectoryTest, RejectsInvalidPathAndOwner)
{
    RuntimeDirectoryError error;
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory("relative", geteuid(), error));
    EXPECT_EQ(error.code, EINVAL);
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory("/", geteuid(), error));
    EXPECT_EQ(error.code, EINVAL);
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory(root_ + "/../run", geteuid(), error));
    EXPECT_EQ(error.code, EINVAL);
    EXPECT_FALSE(EnsurePrivateRuntimeDirectory(root_ + "/run", geteuid() + 1, error));
    EXPECT_EQ(error.code, EACCES);
}

TEST_F(PrivateRuntimeDirectoryTest, RejectsEmbeddedNullBeforeCreatingAnyDirectory)
{
    // 分别覆盖末级截断和祖先截断；必须在任何 mkdirat 之前拒绝整个输入。
    const auto truncated = root_ + "/run";
    const std::string suffix("\0ignored", 8);
    for (const auto &path : {truncated + suffix, root_ + suffix + "/child"}) {
        RuntimeDirectoryError error;
        EXPECT_FALSE(EnsurePrivateRuntimeDirectory(path, geteuid(), error));
        EXPECT_EQ(error.code, EINVAL);
        EXPECT_EQ(error.path, path);
        EXPECT_NE(error.step.find("NUL"), std::string::npos);
    }
    EXPECT_FALSE(std::filesystem::exists(truncated));
    EXPECT_FALSE(std::filesystem::exists(root_ + "/child"));
}
} // 命名空间 virtrust
