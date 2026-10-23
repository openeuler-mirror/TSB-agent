/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include "virtrust/api/admission_test_support.h"

#include <gtest/gtest.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <thread>

#include "tsb_agent/tsb_agent.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/base/logger.h"
#include "virtrust/api/context.h"
#include "virtrust/link/grpc_client.h"

namespace virtrust::test {
AdmissionTestState &AdmissionState()
{
    static AdmissionTestState state;
    return state;
}

TestFd::~TestFd() { Reset(); }
void TestFd::Reset(int fd)
{
    if (fd_ >= 0) {
        close(fd_);
    }
    fd_ = fd;
}

bool ReadByteWithin(int fd, char &value, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            return false;
        }
        pollfd event{fd, POLLIN, 0};
        const int ready = poll(&event, 1, static_cast<int>(remaining.count()));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0 || (event.revents & (POLLIN | POLLHUP)) == 0) {
            return false;
        }
        const auto bytes = read(fd, &value, 1);
        if (bytes < 0 && errno == EINTR) {
            continue;
        }
        return bytes == 1;
    }
    return false;
}

TestChild::TestChild(pid_t pid) : pid_(pid), groupReady_(false)
{
    if (pid_ > 0) {
        groupReady_ = setpgid(pid_, pid_) == 0 || getpgid(pid_) == pid_;
        EXPECT_TRUE(groupReady_) << "Failed to isolate test child process group";
    }
}

bool TestChild::WaitSuccessful(std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        siginfo_t info{};
        if (waitid(P_PID, pid_, &info, WEXITED | WNOHANG | WNOWAIT) == 0) {
            if (info.si_pid == pid_) {
                return info.si_code == CLD_EXITED && info.si_status == 0;
            }
        } else if (errno != EINTR) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

TestChild::~TestChild()
{
    if (pid_ <= 0) {
        return;
    }
    // 组长保留为未回收子进程，整组终止时不会误用已经复用的 PID。
    kill(groupReady_ ? -pid_ : pid_, SIGKILL);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const auto reaped = waitpid(groupReady_ ? -pid_ : pid_, &status, WNOHANG);
        if (reaped < 0 && errno == ECHILD) {
            return;
        }
        if (reaped < 0 && errno != EINTR) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ADD_FAILURE() << "Failed to reap test process group within deadline";
}

namespace {
// GTest 即使用例抛异常或 ASSERT 提前返回也调用 OnTestEnd，统一撤销注入状态。
class AdmissionStateListener : public testing::EmptyTestEventListener {
public:
    void OnTestStart(const testing::TestInfo &) override { Reset(); }
    void OnTestEnd(const testing::TestInfo &) override { Reset(); }
private:
    void Reset()
    {
        auto &state = AdmissionState();
        auto directory = std::move(state.directory);
        auto legacyPath = std::move(state.legacyPath);
        state = AdmissionTestState{};
        state.directory = std::move(directory);
        state.legacyPath = std::move(legacyPath);
        Logger::Instance()->Reset();
        if (!state.directory.empty() && chmod(state.directory.c_str(), 0700) != 0) {
            EXPECT_EQ(errno, ENOENT) << "Failed to restore test directory mode";
        }
    }
};
// 在申请完成的父进程中识别真实锁 fd，供 fork 后、exec 前进行只读核对。
int FindOpenFdForFile(const std::string &path, dev_t &device, ino_t &inode)
{
    struct stat target {};
    if (stat(path.c_str(), &target) != 0) {
        return -1;
    }
    device = target.st_dev;
    inode = target.st_ino;
    DIR *directory = opendir("/proc/self/fd");
    if (directory == nullptr) {
        return -1;
    }
    int result = -1;
    while (const auto *entry = readdir(directory)) {
        char *end = nullptr;
        const long number = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || number < 0 || number > INT_MAX) {
            continue;
        }
        struct stat opened {};
        if (fstat(static_cast<int>(number), &opened) == 0 && opened.st_dev == device && opened.st_ino == inode) {
            result = static_cast<int>(number);
            break;
        }
    }
    closedir(directory);
    return result;
}

// 每个测试进程独占临时目录，不依赖守护进程，也不修改系统运行目录。
class AdmissionEnvironment : public testing::Environment {
public:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-api-admission-XXXXXX";
        const char *path = mkdtemp(pattern);
        ASSERT_NE(path, nullptr);
        root_ = path;
        AdmissionState().directory = root_ + "/runtime";
        AdmissionState().legacyPath = root_ + "/legacy.lock";
        testing::UnitTest::GetInstance()->listeners().Append(new AdmissionStateListener);
    }
    void TearDown() override
    {
        if (!root_.empty()) {
            std::error_code error;
            std::filesystem::remove_all(root_, error);
            EXPECT_FALSE(error) << error.message();
        }
    }
private:
    std::string root_;
};
[[maybe_unused]] auto *environment = testing::AddGlobalTestEnvironment(new AdmissionEnvironment);
} // 匿名命名空间
} // 命名空间 virtrust::test

// 包装默认生产申请，显式传入隔离目录的探针仍调用真实实现。
extern "C" virtrust::LockOutcome RealAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__real__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedAdmission(virtrust::NodeAdmission *, virtrust::AdmissionKind,
    const std::string &, uid_t)
    asm("__wrap__ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj");
extern "C" virtrust::LockOutcome WrappedAdmission(virtrust::NodeAdmission *self, virtrust::AdmissionKind kind,
    const std::string &directory, uid_t owner)
{
    auto &state = virtrust::test::AdmissionState();
    if (directory != "/run/virtrust") {
        return RealAdmission(self, kind, directory, owner);
    }
    // root 字面路径测试的独占探针不是普通 API 调用，不纳入入口申请计数。
    if (state.productionPolicy && kind == virtrust::AdmissionKind::Migration) {
        return RealAdmission(self, kind, directory, owner);
    }
    ++state.admissionCalls;
    EXPECT_EQ(owner, 0U);
    EXPECT_EQ(kind, virtrust::AdmissionKind::OrdinaryMutation);
    if (state.acquireException == 1) {
        throw std::bad_alloc();
    }
    if (state.acquireException == 2) {
        throw 42;
    }
    if (state.productionPolicy) {
        return RealAdmission(self, kind, directory, owner);
    }
    const auto result = RealAdmission(self, kind, state.directory, geteuid());
    if (state.captureForkAdmissionFd && result == virtrust::LockOutcome::Acquired) {
        state.forkAdmissionFd = virtrust::test::FindOpenFdForFile(state.directory + "/node-admission.lock",
            state.forkAdmissionDevice, state.forkAdmissionInode);
    }
    return result;
}

extern "C" int __real_open(const char *, int, ...);
extern "C" virtrust::MigrationResult RealMigrationRpc(virtrust::UdsClientMock *, const virtrust::MigrationConfig &)
    asm("__real__ZN8virtrust13UdsClientMock13DomainMigrateERKNS_15MigrationConfigE");
extern "C" virtrust::MigrationResult WrappedMigrationRpc(virtrust::UdsClientMock *, const virtrust::MigrationConfig &)
    asm("__wrap__ZN8virtrust13UdsClientMock13DomainMigrateERKNS_15MigrationConfigE");
extern "C" virtrust::MigrationResult WrappedMigrationRpc(virtrust::UdsClientMock *client,
    const virtrust::MigrationConfig &config)
{
    auto &state = virtrust::test::AdmissionState();
    ++state.udsCalls;
    if (state.udsResultOverride == -999) {
        return RealMigrationRpc(client, config);
    }
    virtrust::MigrationResult result;
    if (state.udsResultOverride == static_cast<int>(virtrust::VirtrustRc::OK)) {
        result.rc = virtrust::VirtrustRc::OK;
        result.outcome = virtrust::MigrationOutcome::Success;
        result.manualCheckRequired = false;
    } else if (state.udsResultOverride == static_cast<int>(virtrust::VirtrustRc::BUSY)) {
        result.rc = virtrust::VirtrustRc::BUSY;
        result.outcome = virtrust::MigrationOutcome::FailedBeforeEffect;
        result.primaryError = {virtrust::MigrationStage::Preflight, virtrust::MigrationSide::Source,
                               virtrust::MigrationOperation::AcquireAdmission,
                               virtrust::MigrationErrorOrigin::Validation, false, 0};
        result.hasPrimaryError = true;
        result.manualCheckRequired = false;
    } else {
        result.primaryError = {virtrust::MigrationStage::Uds, virtrust::MigrationSide::Source,
                               virtrust::MigrationOperation::NotifyPeer,
                               state.udsResultOverride == -1 ? virtrust::MigrationErrorOrigin::Grpc
                                                             : virtrust::MigrationErrorOrigin::Internal, false, 0};
        result.hasPrimaryError = true;
    }
    return result;
}

extern "C" int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    auto &state = virtrust::test::AdmissionState();
    if (std::strcmp(path, "/tmp/virtrust-start.lock") == 0) {
        if (state.observedConnection != nullptr) {
            EXPECT_EQ(state.observedConnection->GetUri(), state.expectedUriBeforePreparation);
        }
        ++state.legacyOpens;
        if (state.failLegacyOpen) {
            errno = EACCES;
            return -1;
        }
        return __real_open(state.legacyPath.c_str(), flags, mode);
    }
    return __real_open(path, flags, mode);
}

extern "C" int __real_GetVRoots(int *, Description **);
extern "C" int __wrap_GetVRoots(int *count, Description **info)
{
    const auto &state = virtrust::test::AdmissionState();
    if (state.observedConnection != nullptr) {
        EXPECT_EQ(state.observedConnection->GetUri(), state.expectedUriBeforePreparation);
    }
    ++virtrust::test::AdmissionState().businessCalls;
    return __real_GetVRoots(count, info);
}
extern "C" int __real_StartVRoot(char *);
extern "C" int __wrap_StartVRoot(char *uuid)
{
    auto &state = virtrust::test::AdmissionState();
    ++state.businessCalls;
    if (state.throwInBusiness) {
        throw std::runtime_error("Injected business failure");
    }
    return __real_StartVRoot(uuid);
}
extern "C" int __real_StopVRoot(char *);
extern "C" int __wrap_StopVRoot(char *uuid)
{
    ++virtrust::test::AdmissionState().businessCalls;
    return __real_StopVRoot(uuid);
}
extern "C" int __real_RemoveVRoot(char *);
extern "C" int __wrap_RemoveVRoot(char *uuid)
{
    ++virtrust::test::AdmissionState().businessCalls;
    return __real_RemoveVRoot(uuid);
}
