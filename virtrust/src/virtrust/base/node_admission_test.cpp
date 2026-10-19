/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

#include "virtrust/base/node_admission.h"

namespace virtrust {
namespace {
// 断言提前返回时关闭测试管道，避免测试进程泄漏描述符。
struct TestPipe {
    int fd[2]{-1, -1};
    TestPipe() = default;
    TestPipe(const TestPipe &) = delete;
    TestPipe &operator=(const TestPipe &) = delete;
    ~TestPipe()
    {
        Close(0);
        Close(1);
    }
    bool Open()
    {
        return pipe(fd) == 0;
    }
    void Close(int index)
    {
        if (fd[index] >= 0) {
            close(fd[index]);
            fd[index] = -1;
        }
    }
};

// 提前断言失败时仍回收子进程，避免锁测试留下持锁者。
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid)
    {}
    ChildGuard(const ChildGuard &) = delete;
    ChildGuard &operator=(const ChildGuard &) = delete;
    ~ChildGuard()
    {
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            int status = 0;
            // 清理也使用总期限；极端内核阻塞仍由 CTest 的进程级超时兜底。
            if (!Reap(status)) {
                ADD_FAILURE() << "Failed to reap test child after SIGKILL";
            }
        }
    }
    bool ReapSuccessful()
    {
        int status = 0;
        return Reap(status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

private:
    // 正常退出和异常清理共用非阻塞回收，信号中断不重置总期限。
    bool Reap(int &status)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = waitpid(pid_, &status, WNOHANG);
            if (result == pid_) {
                pid_ = -1;
                return true;
            }
            if (result < 0 && errno != EINTR) {
                if (errno == ECHILD) {
                    pid_ = -1;
                }
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    }

    pid_t pid_;
};

bool Receive(int fd, char expected, std::chrono::milliseconds timeout = std::chrono::seconds(3))
{
    pollfd event{fd, POLLIN, 0};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        // 向上取整剩余毫秒，避免不足一毫秒时忙轮询；EINTR 后不重置原期限。
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
        const int result = poll(&event, 1, static_cast<int>(remaining.count()));
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0 || (event.revents & (POLLIN | POLLHUP)) == 0) {
            return false;
        }
        // 管道只有一个读取者，就绪后读一个字节；若被信号中断则重新检查总期限。
        char value = 0;
        const auto bytes = read(fd, &value, 1);
        if (bytes < 0 && errno == EINTR) {
            continue;
        }
        return bytes == 1 && value == expected;
    }
}

// Linux /proc/locks 中的箭头行证明子进程已进入内核 flock 等待。
bool WaitForBlockedFlock(pid_t child)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream locks("/proc/locks");
        std::string line;
        while (std::getline(locks, line)) {
            std::istringstream fields(line);
            std::string id, arrow, kind, advisory, mode;
            pid_t owner = -1;
            if (fields >> id >> arrow >> kind >> advisory >> mode >> owner && arrow == "->" && kind == "FLOCK" &&
                owner == child) {
                return true;
            }
        }
        std::this_thread::yield();
    }
    return false;
}

// 迁移探针使用新进程和新打开文件对象；先关闭 fork 继承的普通准入与业务锁副本。
bool ProbeMigrationInChild(NodeAdmission &inheritedAdmission, ProcessFileLock &inheritedBusiness,
                           const std::string &directory, LockOutcome expected)
{
    const auto child = fork();
    if (child < 0) {
        return false;
    }
    ChildGuard guard(child);
    if (child == 0) {
        inheritedAdmission.Release();
        inheritedBusiness.Release();
        NodeAdmission migration;
        _exit(migration.TryAcquire(AdmissionKind::Migration, directory, geteuid()) == expected ? 0 : 1);
    }
    return guard.ReapSuccessful();
}

volatile sig_atomic_t signalSeen = 0;

// 信号处理器只写入信号安全标志，不调用日志、分配或测试断言。
void MarkSignal(int)
{
    signalSeen = 1;
}

// 用例结束时恢复原信号处理，避免污染同一测试进程中的后续用例。
class ScopedSignalHandler {
public:
    ScopedSignalHandler()
    {
        struct sigaction action {};
        action.sa_handler = MarkSignal;
        sigemptyset(&action.sa_mask);
        installed_ = sigaction(SIGUSR1, &action, &previous_) == 0;
    }
    ~ScopedSignalHandler()
    {
        if (installed_) {
            sigaction(SIGUSR1, &previous_, nullptr);
        }
    }
    ScopedSignalHandler(const ScopedSignalHandler &) = delete;
    ScopedSignalHandler &operator=(const ScopedSignalHandler &) = delete;
    bool Installed() const { return installed_; }

private:
    struct sigaction previous_ {};
    bool installed_ = false;
};
} // 匿名命名空间

TEST(NodeAdmissionTestSupportTest, SignalsDoNotRestartReceiveDeadline)
{
    signalSeen = 0;
    ScopedSignalHandler handler;
    ASSERT_TRUE(handler.Installed());
    TestPipe pipe;
    ASSERT_TRUE(pipe.Open());
    const auto parent = getpid();
    const auto child = fork();
    ASSERT_GE(child, 0);
    ChildGuard guard(child);
    if (child == 0) {
        // 连续中断超过接收期限；不能每次 EINTR 都重新等待完整期限。
        for (int i = 0; i < 100; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (kill(parent, SIGUSR1) != 0) {
                _exit(1);
            }
        }
        _exit(0);
    }
    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(Receive(pipe.fd[0], 'X', std::chrono::milliseconds(100)));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_NE(signalSeen, 0);
    // 给调度留下余量；这个断言证明总期限不会被约一秒的信号流重置。
    EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}

TEST(NodeAdmissionTestSupportTest, GuardReapsChildOnEarlyScopeExit)
{
    const auto child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    {
        ChildGuard guard(child);
        // 不显式调用 ReapSuccessful，模拟断言导致的提前退出。
    }
    int status = 0;
    EXPECT_EQ(waitpid(child, &status, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
}

class NodeAdmissionTest : public testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-admission-ut.XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        root_ = created;
        directory_ = root_ + "/run";
    }
    void TearDown() override
    {
        if (!root_.empty()) {
            std::filesystem::remove_all(root_);
        }
    }
    std::string root_;
    std::string directory_;
};

TEST_F(NodeAdmissionTest, SharedHoldersExcludeMigrationUntilBothRelease)
{
    NodeAdmission first, second, migration;
    ASSERT_EQ(first.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Acquired);
    ASSERT_EQ(second.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Busy);
    EXPECT_FALSE(migration.OwnsAdmission());
    EXPECT_NE(migration.LastError().find("node-admission.lock"), std::string::npos);
    first.Release();
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Busy);
    second.Release();
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(migration.LastErrno(), 0);
    EXPECT_TRUE(migration.LastError().empty());
}

TEST_F(NodeAdmissionTest, MigrationExcludesBothKindsAndInstanceLockIsIndependent)
{
    NodeAdmission migration, ordinary, next;
    ASSERT_EQ(migration.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Busy);
    EXPECT_EQ(next.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Busy);
    ProcessFileLock instance;
    EXPECT_EQ(instance.Acquire(directory_ + "/libvirtrustd.lock", LockMode::Exclusive, LockWait::Try),
              LockOutcome::Acquired);
    migration.Release();
    EXPECT_EQ(ordinary.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Acquired);
}

TEST_F(NodeAdmissionTest, RepeatedAcquireAndInvalidKindAreErrors)
{
    NodeAdmission holder, contender;
    ASSERT_EQ(holder.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(holder.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Error);
    EXPECT_EQ(holder.LastErrno(), EALREADY);
    EXPECT_TRUE(holder.OwnsAdmission());
    EXPECT_EQ(contender.TryAcquire(static_cast<AdmissionKind>(-1), directory_, geteuid()), LockOutcome::Error);
    EXPECT_EQ(contender.LastErrno(), EINVAL);
    EXPECT_EQ(contender.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Busy);
}

TEST_F(NodeAdmissionTest, DirectoryFailureIsErrorAndCanRecover)
{
    NodeAdmission admission;
    EXPECT_EQ(admission.TryAcquire(AdmissionKind::Migration, root_ + "/missing/run", geteuid()),
              LockOutcome::Error);
    EXPECT_EQ(admission.LastErrno(), ENOENT);
    EXPECT_FALSE(admission.OwnsAdmission());
    EXPECT_EQ(admission.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
}

TEST_F(NodeAdmissionTest, EmbeddedNullIsRejectedWithoutSideEffectsAndCanRecover)
{
    NodeAdmission admission;
    const auto invalid = directory_ + std::string("\0ignored", 8);
    EXPECT_EQ(admission.TryAcquire(AdmissionKind::Migration, invalid, geteuid()), LockOutcome::Error);
    EXPECT_EQ(admission.LastErrno(), EINVAL);
    EXPECT_NE(admission.LastError().find("NUL"), std::string::npos);
    EXPECT_FALSE(admission.OwnsAdmission());
    EXPECT_FALSE(std::filesystem::exists(directory_));
    ASSERT_EQ(admission.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
    EXPECT_EQ(admission.LastErrno(), 0);
    EXPECT_TRUE(admission.LastError().empty());
}

TEST_F(NodeAdmissionTest, UnsafeLockFileIsErrorRatherThanBusy)
{
    const auto lockPath = directory_ + "/node-admission.lock";
    ASSERT_EQ(mkdir(directory_.c_str(), 0700), 0);
    ASSERT_EQ(symlink("another-file", lockPath.c_str()), 0);
    NodeAdmission admission;
    EXPECT_EQ(admission.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Error);
    EXPECT_EQ(admission.LastErrno(), ELOOP);
    EXPECT_FALSE(admission.OwnsAdmission());
    EXPECT_NE(admission.LastError().find(lockPath), std::string::npos);
}

TEST_F(NodeAdmissionTest, MoveTransfersLockAndDestructorReleasesIt)
{
    NodeAdmission contender;
    {
        NodeAdmission first;
        ASSERT_EQ(first.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
        NodeAdmission second(std::move(first));
        EXPECT_FALSE(first.OwnsAdmission());
        NodeAdmission target;
        const auto other = root_ + "/other";
        ASSERT_EQ(target.TryAcquire(AdmissionKind::Migration, other, geteuid()), LockOutcome::Acquired);
        target = std::move(second);
        EXPECT_FALSE(second.OwnsAdmission());
        EXPECT_TRUE(target.OwnsAdmission());
        NodeAdmission freed;
        EXPECT_EQ(freed.TryAcquire(AdmissionKind::Migration, other, geteuid()), LockOutcome::Acquired);
        auto &self = target;
        target = std::move(self);
        EXPECT_EQ(contender.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Busy);
    }
    EXPECT_EQ(contender.TryAcquire(AdmissionKind::Migration, directory_, geteuid()), LockOutcome::Acquired);
    contender.Release();
    contender.Release();
    EXPECT_TRUE(std::filesystem::exists(directory_ + "/node-admission.lock"));
}

TEST_F(NodeAdmissionTest, WaitingOrdinaryHolderContinuesToExcludeMigration)
{
    NodeAdmission first;
    ASSERT_EQ(first.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()), LockOutcome::Acquired);
    ProcessFileLock business;
    const auto businessPath = directory_ + "/business.lock";
    ASSERT_EQ(business.Acquire(businessPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    TestPipe ready, control;
    ASSERT_TRUE(ready.Open());
    ASSERT_TRUE(control.Open());
    const auto child = fork();
    ASSERT_GE(child, 0);
    ChildGuard guard(child);
    if (child == 0) {
        ready.Close(0);
        control.Close(1);
        // fork 副本共享内核打开文件对象，先关闭父令牌副本再独立申请。
        first.Release();
        business.Release();
        NodeAdmission second;
        if (second.TryAcquire(AdmissionKind::OrdinaryMutation, directory_, geteuid()) != LockOutcome::Acquired ||
            write(ready.fd[1], "R", 1) != 1) {
            _exit(1);
        }
        ProcessFileLock waitingBusiness;
        if (waitingBusiness.Acquire(businessPath, LockMode::Exclusive, LockWait::Block) != LockOutcome::Acquired ||
            write(ready.fd[1], "B", 1) != 1) {
            _exit(2);
        }
        char release = 0;
        if (read(control.fd[0], &release, 1) != 1 || release != 'X') {
            _exit(3);
        }
        waitingBusiness.Release();
        second.Release();
        _exit(0);
    }
    ready.Close(1);
    control.Close(0);
    ASSERT_TRUE(Receive(ready.fd[0], 'R'));
    ASSERT_TRUE(WaitForBlockedFlock(child));
    EXPECT_TRUE(ProbeMigrationInChild(first, business, directory_, LockOutcome::Busy));
    business.Release();
    first.Release();
    ASSERT_TRUE(Receive(ready.fd[0], 'B'));
    EXPECT_TRUE(ProbeMigrationInChild(first, business, directory_, LockOutcome::Busy));
    ASSERT_EQ(write(control.fd[1], "X", 1), 1);
    ASSERT_TRUE(guard.ReapSuccessful());
    EXPECT_TRUE(ProbeMigrationInChild(first, business, directory_, LockOutcome::Acquired));
}
} // 命名空间 virtrust
