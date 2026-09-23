/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "libvirtrustd/daemon_instance.h"
#include <gtest/gtest.h>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <new>

namespace {
// 仅在当前测试线程显式启用时，使一次分配失败；抛出前立即关闭，允许错误诊断分配。
thread_local bool failNextAllocation = false;
// 逐个分配点注入，覆盖目录打开之后的路径拼接异常；-1 表示关闭。
thread_local int failAllocationAfter = -1;
}

void *operator new(std::size_t size)
{
    if (failNextAllocation || failAllocationAfter == 0) {
        failNextAllocation = false;
        failAllocationAfter = -1;
        throw std::bad_alloc();
    }
    if (failAllocationAfter > 0) { --failAllocationAfter; }
    if (void *memory = std::malloc(size == 0 ? 1 : size)) { return memory; }
    throw std::bad_alloc();
}
void operator delete(void *memory) noexcept { std::free(memory); }
void operator delete(void *memory, std::size_t) noexcept { std::free(memory); }

namespace virtrust {
// 只操作本用例临时目录；不触碰实际 /run/virtrust 或系统服务。
class DaemonInstanceTest : public testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-instance-ut.XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        root = created;
        directory = root + "/run";
    }
    void TearDown() override { if (!root.empty()) { std::filesystem::remove_all(root); } }
    std::string root, directory;
};

TEST_F(DaemonInstanceTest, CreatesPrivateDirectoryAndExcludesSecondInstance)
{
    {
        DaemonInstance first, second;
        ASSERT_EQ(first.Acquire(directory, geteuid()), LockOutcome::Acquired) << first.LastErrno();
        struct stat info {};
        ASSERT_EQ(stat(directory.c_str(), &info), 0);
        EXPECT_EQ(info.st_mode & 07777, 0700u);
        EXPECT_EQ(second.Acquire(directory, geteuid()), LockOutcome::Busy);
    }
    DaemonInstance next;
    EXPECT_EQ(next.Acquire(directory, geteuid()), LockOutcome::Acquired);
    EXPECT_TRUE(std::filesystem::exists(directory + "/libvirtrustd.lock"));
}

TEST_F(DaemonInstanceTest, UnsafeDirectoryIsRejectedWithoutChangingPermissions)
{
    ASSERT_EQ(mkdir(directory.c_str(), 0700), 0);
    ASSERT_EQ(chmod(directory.c_str(), 0755), 0);
    DaemonInstance instance;
    EXPECT_EQ(instance.Acquire(directory, geteuid()), LockOutcome::Error);
    EXPECT_EQ(instance.LastErrno(), EACCES);
    struct stat info {};
    ASSERT_EQ(stat(directory.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 07777, 0755u);
    EXPECT_FALSE(std::filesystem::exists(directory + "/libvirtrustd.lock"));
}

TEST_F(DaemonInstanceTest, RejectsSymlinkAndWrongExpectedOwner)
{
    ASSERT_EQ(symlink(root.c_str(), directory.c_str()), 0);
    DaemonInstance instance;
    EXPECT_EQ(instance.Acquire(directory, geteuid()), LockOutcome::Error);
    ASSERT_EQ(unlink(directory.c_str()), 0);
    ASSERT_EQ(mkdir(directory.c_str(), 0700), 0);
    EXPECT_EQ(instance.Acquire(directory, geteuid() + 1), LockOutcome::Error);
    EXPECT_EQ(instance.LastErrno(), EACCES);
}

TEST_F(DaemonInstanceTest, ChildCannotAcquireWhileParentLives)
{
    DaemonInstance parent;
    ASSERT_EQ(parent.Acquire(directory, geteuid()), LockOutcome::Acquired);
    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        DaemonInstance contender;
        _exit(contender.Acquire(directory, geteuid()) == LockOutcome::Busy ? 0 : 1);
    }
    int status = 0;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    ASSERT_EQ(result, child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

// 首实例正常监听后，第二实例必须在触碰同一路径之前被拒绝。
TEST_F(DaemonInstanceTest, RuntimeRejectsSecondWithoutTouchingSocket)
{
    LinkConfig config {};
    config.ip = "127.0.0.1";
    config.udsPath = root + "/rpc.sock";
    {
        DaemonRuntime first(config, directory, geteuid());
        ASSERT_EQ(first.Start(), LockOutcome::Acquired);
        struct stat before {};
        ASSERT_EQ(lstat(config.udsPath.c_str(), &before), 0);
        DaemonRuntime second(config, directory, geteuid());
        EXPECT_EQ(second.Start(), LockOutcome::Busy);
        struct stat after {};
        ASSERT_EQ(lstat(config.udsPath.c_str(), &after), 0);
        EXPECT_EQ(before.st_ino, after.st_ino);
        EXPECT_EQ(before.st_dev, after.st_dev);
    }
    DaemonRuntime next(config, directory, geteuid());
    EXPECT_EQ(next.Start(), LockOutcome::Acquired);
}

TEST_F(DaemonInstanceTest, FailedRuntimeReleasesInstanceBeforeDestruction)
{
    LinkConfig config {};
    config.ip = "127.0.0.1";
    config.udsPath = root + "/missing/rpc.sock";
    DaemonRuntime failed(config, directory, geteuid());
    EXPECT_EQ(failed.Start(), LockOutcome::Error);
    EXPECT_FALSE(failed.LastError().empty());
    config.udsPath = root + "/rpc.sock";
    DaemonRuntime next(config, directory, geteuid());
    EXPECT_EQ(next.Start(), LockOutcome::Acquired);
}
TEST_F(DaemonInstanceTest, RejectsSymlinkInAncestorAndRelativePaths)
{
    const std::string alias = root + "/alias";
    ASSERT_EQ(symlink(root.c_str(), alias.c_str()), 0);
    DaemonInstance instance;
    EXPECT_EQ(instance.Acquire(alias + "/run", geteuid()), LockOutcome::Error);
    EXPECT_FALSE(std::filesystem::exists(directory));
    EXPECT_EQ(instance.Acquire("relative/run", geteuid()), LockOutcome::Error);
}

TEST_F(DaemonInstanceTest, RuntimeErrorNamesFailedDirectoryAndStep)
{
    ASSERT_EQ(mkdir(directory.c_str(), 0700), 0);
    ASSERT_EQ(chmod(directory.c_str(), 0755), 0);
    LinkConfig config {};
    DaemonRuntime runtime(config, directory, geteuid());
    EXPECT_EQ(runtime.Start(), LockOutcome::Error);
    EXPECT_NE(runtime.LastError().find(directory), std::string::npos);
    EXPECT_NE(runtime.LastError().find("permissions"), std::string::npos);
    EXPECT_NE(runtime.LastError().find("0700"), std::string::npos);
}

TEST_F(DaemonInstanceTest, StartupExceptionBecomesErrorAndDoesNotKeepInstance)
{
    LinkConfig config {};
    DaemonRuntime runtime(config, directory, geteuid());
    LockOutcome result = LockOutcome::Acquired;
    bool escaped = false;
    failNextAllocation = true;
    try { result = runtime.Start(); } catch (...) { escaped = true; }
    failNextAllocation = false;
    EXPECT_FALSE(escaped);
    EXPECT_EQ(result, LockOutcome::Error);
    EXPECT_FALSE(runtime.LastError().empty());
    DaemonInstance next;
    EXPECT_EQ(next.Acquire(directory, geteuid()), LockOutcome::Acquired);
}

TEST_F(DaemonInstanceTest, DirectoryAllocationFailuresDoNotLeakDescriptors)
{
    ASSERT_EQ(mkdir(directory.c_str(), 0700), 0);
    const auto countDescriptors = [] {
        std::size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator("/proc/self/fd")) {
            (void)entry;
            ++count;
        }
        return count;
    };
    const auto before = countDescriptors();
    int failures = 0, successes = 0;
    for (int point = 0; point < 80; ++point) {
        {
            DaemonInstance instance;
            failAllocationAfter = point;
            try {
                const auto result = instance.Acquire(directory, geteuid());
                failAllocationAfter = -1;
                ASSERT_EQ(result, LockOutcome::Acquired);
                ++successes;
            } catch (const std::bad_alloc &) {
                failAllocationAfter = -1;
                ++failures;
            }
        }
        EXPECT_EQ(countDescriptors(), before) << "Allocation failure point " << point;
    }
    EXPECT_GT(failures, 0);
    EXPECT_GT(successes, 0);
}

TEST_F(DaemonInstanceTest, RepeatedStartExceptionDoesNotReleaseExistingInstance)
{
    LinkConfig config {};
    config.ip = "127.0.0.1";
    config.udsPath = root + "/rpc.sock";
    DaemonRuntime runtime(config, directory, geteuid());
    ASSERT_EQ(runtime.Start(), LockOutcome::Acquired);
    LockOutcome result = LockOutcome::Acquired;
    bool escaped = false;
    failNextAllocation = true;
    try { result = runtime.Start(); } catch (...) { escaped = true; }
    failNextAllocation = false;
    EXPECT_FALSE(escaped);
    EXPECT_EQ(result, LockOutcome::Error);
    DaemonInstance contender;
    EXPECT_EQ(contender.Acquire(directory, geteuid()), LockOutcome::Busy);
    EXPECT_TRUE(std::filesystem::is_socket(config.udsPath));
}
} // 命名空间 virtrust
