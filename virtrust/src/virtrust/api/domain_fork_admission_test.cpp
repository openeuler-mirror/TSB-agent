/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

#include "virtrust/api/admission_test_support.h"
#include "virtrust/api/domain.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/base/process_file_lock.h"
#include "tsb_agent/tsb_agent.h"
#include "virtrust/base/custom_logger.h"

extern "C" int __real_CreateVRoot(Description *description);
extern "C" int __wrap_CreateVRoot(Description *description)
{
    ++virtrust::test::AdmissionState().createVrootCalls;
    return __real_CreateVRoot(description);
}

extern "C" pid_t __real_waitpid(pid_t pid, int *status, int options);
extern "C" pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    auto &state = virtrust::test::AdmissionState();
    if (state.observeBusinessWait && pid > 0 && options == 0) {
        ++state.waitCalls;
        state.waitedChild = pid;
        EXPECT_EQ(state.createVrootCalls, 0);
        // 每次等待（包括重试）都必须仍持有两层锁。
        virtrust::NodeAdmission migration;
        EXPECT_EQ(migration.TryAcquire(virtrust::AdmissionKind::Migration, state.directory, geteuid()),
            virtrust::LockOutcome::Busy);
        virtrust::ProcessFileLock legacy;
        EXPECT_EQ(legacy.Acquire(state.legacyPath, virtrust::LockMode::Exclusive, virtrust::LockWait::Try),
            virtrust::LockOutcome::Busy);
        if (state.waitInterruptions > 0) {
            --state.waitInterruptions;
            // 错误返回时 status 无效；故意留下成功形态，检测调用方是否错误地使用它。
            *status = 0;
            errno = EINTR;
            return -1;
        }
        if (state.waitFailure != 0) {
            // 先真实回收，模拟其他回收者已处理子进程；不制造脱离测试控制的进程。
            int ignored = 0;
            pid_t reaped;
            do { reaped = __real_waitpid(pid, &ignored, 0); } while (reaped == -1 && errno == EINTR);
            EXPECT_EQ(reaped, pid);
            *status = 0;
            errno = state.waitFailure;
            return -1;
        }
    }
    const auto result = __real_waitpid(pid, status, options);
    if (result > 0 && status != nullptr && WIFEXITED(*status)) {
        virtrust::test::AdmissionState().lastReapedExitCode = WEXITSTATUS(*status);
    }
    return result;
}

extern "C" int __real_execv(const char *path, char *const argv[]);
extern "C" int __wrap_execv(const char *path, char *const argv[])
{
    // fork 后不分配内存；在真实 exec 前检查锁描述符与最终连接参数。
    const auto &state = virtrust::test::AdmissionState();
    if (state.forkProbeWriteFd >= 0) {
        char result = '?';
        if (state.forkAdmissionFd >= 0) {
            struct stat opened {};
            const int inspected = fstat(state.forkAdmissionFd, &opened);
            if ((inspected == -1 && errno == EBADF) || (inspected == 0 &&
                (opened.st_dev != state.forkAdmissionDevice || opened.st_ino != state.forkAdmissionInode))) {
                result = 'C';
            } else if (inspected == 0) {
                result = 'L';
            }
        }
        if (write(state.forkProbeWriteFd, &result, 1) != 1) { _exit(126); }
    }
    if (state.execArgsProbeFd >= 0) {
        int connectCount = 0;
        bool matched = false;
        for (size_t i = 0; argv[i] != nullptr; ++i) {
            const char *uri = nullptr;
            if (std::strcmp(argv[i], "--connect") == 0 && argv[i + 1] != nullptr) {
                uri = argv[++i];
            } else if (std::strncmp(argv[i], "--connect=", 10) == 0) {
                uri = argv[i] + 10;
            } else if (std::strcmp(argv[i], "-c") == 0 && argv[i + 1] != nullptr) {
                uri = argv[++i];
            } else if (std::strncmp(argv[i], "-c", 2) == 0 && argv[i][2] != '\0') {
                uri = argv[i] + 2;
            }
            if (uri != nullptr) {
                ++connectCount;
                matched = std::strcmp(uri, state.expectedExecUri.c_str()) == 0;
            }
        }
        const char result = connectCount == 1 && matched ? 'A' : 'F';
        if (write(state.execArgsProbeFd, &result, 1) != 1) { _exit(126); }
    }
    const int result = __real_execv(path, argv);
    const int savedError = errno;
    if (state.execFailureProbeFd >= 0) {
        const char reason = result == -1 && savedError == ENOENT ? 'N' :
            (result == -1 && savedError == EACCES ? 'P' : '?');
        if (write(state.execFailureProbeFd, &reason, 1) != 1) { _exit(126); }
    }
    errno = savedError;
    return result;
}

namespace virtrust {
namespace {
// 接管工作进程退出后留下的后代，使进程组清理能够回收全部测试子进程。
class DomainForkAdmissionTest : public testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_EQ(prctl(PR_GET_CHILD_SUBREAPER, &previousSubreaper_), 0);
        ASSERT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
    }
    void TearDown() override { EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, previousSubreaper_), 0); }
private:
    int previousSubreaper_ = 0;
};

// 管道使用 CLOEXEC，断言提前返回时自动关闭。
struct TestPipe {
    test::TestFd readEnd;
    test::TestFd writeEnd;
    bool Open()
    {
        int fd[2];
        if (pipe2(fd, O_CLOEXEC) != 0) { return false; }
        readEnd.Reset(fd[0]);
        writeEnd.Reset(fd[1]);
        return true;
    }
};

// 使用 mock 中确实存在的虚机，避免后续查找失败掩盖误入可信资源创建的问题。
void CheckExecFailure(const std::string &program, char expectedReason)
{
    TestPipe failure;
    ASSERT_TRUE(failure.Open());
    auto &state = test::AdmissionState();
    state.execFailureProbeFd = failure.writeEnd.Get();
    const pid_t worker = fork();
    ASSERT_GE(worker, 0);
    if (worker == 0) {
        if (setpgid(0, 0) != 0) { _exit(125); }
        try {
            auto conn = std::make_unique<ConnCtx>();
            if (!conn->Connect()) { _exit(124); }
            EXPECT_EQ(DomainCreate(conn, {program, "--name", "test-domain-1"}), VirtrustRc::ERROR);
            EXPECT_EQ(state.lastReapedExitCode, 127);
            EXPECT_EQ(state.createVrootCalls, 0);
            EXPECT_EQ(state.admissionCalls, 1);
            NodeAdmission migration;
            EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()),
                LockOutcome::Acquired);
            ProcessFileLock legacy;
            EXPECT_EQ(legacy.Acquire(state.legacyPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
            _exit(testing::Test::HasFailure() ? 1 : 0);
        } catch (...) {
            _exit(123);
        }
    }
    test::TestChild child(worker);
    failure.writeEnd.Reset();
    char reason = '?';
    ASSERT_TRUE(test::ReadByteWithin(failure.readEnd.Get(), reason));
    EXPECT_EQ(reason, expectedReason);
    EXPECT_TRUE(child.WaitSuccessful());
}

TEST_F(DomainForkAdmissionTest, MissingExecutableFailsWithoutCreatingTrustedResource)
{
    const auto path = test::AdmissionState().legacyPath + ".missing";
    ASSERT_FALSE(std::filesystem::exists(path));
    CheckExecFailure(path, 'N');
}

TEST_F(DomainForkAdmissionTest, NonExecutableFileFailsWithoutCreatingTrustedResource)
{
    const auto path = test::AdmissionState().legacyPath + ".not-executable";
    test::TestFd file(open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600));
    ASSERT_GE(file.Get(), 0);
    struct Cleanup {
        const std::string &path;
        ~Cleanup() { unlink(path.c_str()); }
    } cleanup{path};
    // 明确无任何执行位，root 和非 root 均应得到真实 EACCES。
    ASSERT_EQ(fchmod(file.Get(), 0600), 0);
    CheckExecFailure(path, 'P');
}

// 正常可执行程序隔离了 exec 失败因素，观察 EINTR 重试与非 EINTR 错误分流。
void CheckWaitResult(int interruptions, int failure)
{
    const pid_t worker = fork();
    ASSERT_GE(worker, 0);
    if (worker == 0) {
        if (setpgid(0, 0) != 0) { _exit(125); }
        try {
            auto conn = std::make_unique<ConnCtx>();
            if (!conn->Connect()) { _exit(124); }
            auto &state = test::AdmissionState();
            state.observeBusinessWait = true;
            state.waitInterruptions = interruptions;
            state.waitFailure = failure;
            std::string diagnostic;
            Logger::Instance()->SetCustomLogFunction([&diagnostic](LogLevel level, std::string_view message) {
                if (level == LogLevel::ERROR) { diagnostic.append(message); }
            });
            const auto result = DomainCreate(conn, {"/bin/true", "--name", "test-domain-1"});
            Logger::Instance()->Reset();
            EXPECT_EQ(state.waitCalls, interruptions + 1);
            EXPECT_EQ(state.waitInterruptions, 0);
            if (failure != 0) {
                EXPECT_EQ(result, VirtrustRc::ERROR);
                EXPECT_EQ(state.createVrootCalls, 0);
                EXPECT_NE(diagnostic.find("Failed to wait for child"), std::string::npos);
                EXPECT_NE(diagnostic.find("errno: " + std::to_string(failure)), std::string::npos);
                EXPECT_NE(diagnostic.find("pid: " + std::to_string(state.waitedChild)), std::string::npos);
            } else {
                // mock 中可信资源已存在，最终业务结果不用于判断 waitpid 是否成功。
                EXPECT_EQ(state.lastReapedExitCode, 0);
                EXPECT_EQ(state.createVrootCalls, 1);
            }
            NodeAdmission migration;
            EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()),
                LockOutcome::Acquired);
            ProcessFileLock legacy;
            EXPECT_EQ(legacy.Acquire(state.legacyPath, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
            _exit(testing::Test::HasFailure() ? 1 : 0);
        } catch (...) { _exit(123); }
    }
    test::TestChild child(worker);
    EXPECT_TRUE(child.WaitSuccessful());
}

TEST_F(DomainForkAdmissionTest, InterruptedWaitRetriesBeforeCreatingTrustedResource)
{
    CheckWaitResult(2, 0);
}

TEST_F(DomainForkAdmissionTest, FailedWaitReportsErrorWithoutCreatingTrustedResource)
{
    CheckWaitResult(0, ECHILD);
    CheckWaitResult(1, EINVAL);
}

// 子进程退出码包含其内部 GTest 断言结果，避免只打印失败却让父测试通过。
[[noreturn]] void RunCreate(const std::vector<std::string> &args)
{
    if (setpgid(0, 0) != 0) { _exit(125); }
    try {
        auto conn = std::make_unique<ConnCtx>();
        if (!test::AdmissionState().expectedExecUri.empty() &&
            !conn->SetUri(test::AdmissionState().expectedExecUri)) { _exit(121); }
        if (!conn->Connect()) { _exit(124); }
        auto &state = test::AdmissionState();
        state.observedConnection = conn.get();
        state.expectedUriBeforePreparation = conn->GetUri();
        const auto rc = DomainCreate(conn, args);
        // mock 没有新建的 test-vm 定义；此 ERROR 不是 exec 失败的验证证据。
        _exit(rc == VirtrustRc::ERROR && state.admissionCalls == 1 &&
            !testing::Test::HasFailure() ? 0 : 123);
    } catch (...) {
        _exit(122);
    }
}

TEST_F(DomainForkAdmissionTest, ParentRetainsQualificationWhileChildExecutes)
{
    auto &state = test::AdmissionState();
    const std::string marker = state.directory + "/child-started";
    const std::string releasePath = state.legacyPath + ".release";
    const std::string scriptPath = state.directory + "/wait-for-release.sh";
    ASSERT_EQ(mkfifo(releasePath.c_str(), 0600), 0);
    {
        std::ofstream script(scriptPath);
        ASSERT_TRUE(script.is_open());
        script << "#!/bin/sh\ntouch " << marker << "\nread token < " << releasePath << "\n";
    }
    ASSERT_EQ(chmod(scriptPath.c_str(), 0700), 0);
    // 同一进程重复运行时也清除 FIFO 和标记。
    struct FifoCleanup {
        const std::string &path;
        const std::string &marker;
        const std::string &script;
        ~FifoCleanup() { unlink(path.c_str()); unlink(marker.c_str()); unlink(script.c_str()); }
    } cleanup{releasePath, marker, scriptPath};
    test::TestFd releaseFd(open(releasePath.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK));
    ASSERT_GE(releaseFd.Get(), 0);
    TestPipe probe;
    ASSERT_TRUE(probe.Open());
    state.captureForkAdmissionFd = true;
    state.forkProbeWriteFd = probe.writeEnd.Get();
    const std::vector<std::string> args{scriptPath, "--name", "test-vm"};
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) { RunCreate(args); }
    test::TestChild child(pid);
    probe.writeEnd.Reset();
    char childFdState = '?';
    ASSERT_TRUE(test::ReadByteWithin(probe.readEnd.Get(), childFdState));
    EXPECT_EQ(childFdState, 'C');
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!std::filesystem::exists(marker) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(std::filesystem::exists(marker));
    NodeAdmission migration;
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Busy);
    const char token = '\n';
    ASSERT_EQ(write(releaseFd.Get(), &token, 1), 1);
    ASSERT_TRUE(child.WaitSuccessful());
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, state.directory, geteuid()), LockOutcome::Acquired);
}

TEST_F(DomainForkAdmissionTest, FinalExecArgumentsPreserveDefaultAndExplicitConnection)
{
    for (bool explicitUri : {false, true}) {
        SCOPED_TRACE(explicitUri);
        auto &state = test::AdmissionState();
        auto conn = std::make_unique<ConnCtx>();
        state.expectedExecUri = explicitUri ? "qemu:///other" : conn->GetUri();
        TestPipe probe;
        ASSERT_TRUE(probe.Open());
        state.execArgsProbeFd = probe.writeEnd.Get();
        std::vector<std::string> args{"/bin/true", "--name", "test-vm"};
        if (explicitUri) {
            args.push_back("--connect=" + state.expectedExecUri);
            args.push_back("-c" + state.expectedExecUri);
        }
        const pid_t pid = fork();
        ASSERT_GE(pid, 0);
        if (pid == 0) { RunCreate(args); }
        test::TestChild child(pid);
        probe.writeEnd.Reset();
        char observed = '?';
        ASSERT_TRUE(test::ReadByteWithin(probe.readEnd.Get(), observed));
        EXPECT_EQ(observed, 'A');
        EXPECT_TRUE(child.WaitSuccessful());
    }
}

TEST_F(DomainForkAdmissionTest, TimeoutCleanupReapsWorkerAndDescendantAndReleasesLock)
{
    TestPipe ready;
    ASSERT_TRUE(ready.Open());
    const pid_t worker = fork();
    ASSERT_GE(worker, 0);
    if (worker == 0) {
        if (setpgid(0, 0) != 0) { _exit(1); }
        const pid_t descendant = fork();
        if (descendant < 0) { _exit(2); }
        if (descendant == 0) {
            NodeAdmission admission;
            if (admission.TryAcquire(AdmissionKind::Migration, test::AdmissionState().directory, geteuid()) !=
                LockOutcome::Acquired) { _exit(3); }
            const char token = 'R';
            if (write(ready.writeEnd.Get(), &token, 1) != 1) { _exit(4); }
        }
        for (;;) { pause(); }
    }
    {
        test::TestChild child(worker);
        ready.writeEnd.Reset();
        char token = '?';
        ASSERT_TRUE(test::ReadByteWithin(ready.readEnd.Get(), token));
        ASSERT_EQ(token, 'R');
        EXPECT_FALSE(child.WaitSuccessful(std::chrono::milliseconds(30)));
        // 模拟提前退出作用域，析构负责回收整组并释放后代持有的锁。
    }
    int status = 0;
    EXPECT_EQ(waitpid(-worker, &status, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
    NodeAdmission migration;
    EXPECT_EQ(migration.TryAcquire(AdmissionKind::Migration, test::AdmissionState().directory, geteuid()),
        LockOutcome::Acquired);
}
} // 匿名命名空间
} // 命名空间 virtrust
