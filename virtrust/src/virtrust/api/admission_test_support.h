/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#pragma once

#include <sys/types.h>

#include <string>
#include <chrono>

namespace virtrust { class ConnCtx; }

namespace virtrust::test {
// 仅链接到测试可执行文件；生产库不提供目录重定向或故障注入开关。
struct AdmissionTestState {
    std::string directory;
    std::string legacyPath;
    bool productionPolicy = false;
    int acquireException = 0;
    int admissionCalls = 0;
    int legacyOpens = 0;
    int businessCalls = 0;
    int udsCalls = 0;
    int udsResultOverride = -999;
    int getVRootsOverride = 0;
    // 1 注入负数量，2 注入正数量但空指针；两者都模拟 TSB 返回成功后的畸形输出。
    int malformedGetVRoots = 0;
    // 注入底层已分配输出后失败：1 为 TSB 错误，2 为成功但数量为负。
    int allocatedGetVRootsFailure = 0;
    bool failLegacyOpen = false;
    bool throwInBusiness = false;
    // 仅供 fork 专用测试在 execv 前核对继承的节点准入描述符。
    bool captureForkAdmissionFd = false;
    int forkAdmissionFd = -1;
    dev_t forkAdmissionDevice = 0;
    ino_t forkAdmissionInode = 0;
    int forkProbeWriteFd = -1;
    // 在旧锁打开和数量检查处观察 URI，防止连接副作用提前到锁外。
    const ConnCtx *observedConnection = nullptr;
    std::string expectedUriBeforePreparation;
    std::string expectedExecUri;
    int execArgsProbeFd = -1;
    // exec 启动失败回归：记录真实 errno、回收的退出码和可信资源创建次数。
    int execFailureProbeFd = -1;
    int lastReapedExitCode = -1;
    int createVrootCalls = 0;
    // 等待故障仅注入业务的阻塞 waitpid；测试清理的非阻塞回收不受影响。
    bool observeBusinessWait = false;
    int waitCalls = 0;
    int waitInterruptions = 0;
    int waitFailure = 0;
    pid_t waitedChild = -1;
};
AdmissionTestState &AdmissionState();
bool WasFailedGetVRootsOutputFreed();
void ResetFailedGetVRootsOutputTracking();

// 测试资源采用作用域所有权，断言提前返回或抛异常时仍关闭描述符。
class TestFd {
public:
    explicit TestFd(int fd = -1) : fd_(fd) {}
    ~TestFd();
    TestFd(const TestFd &) = delete;
    TestFd &operator=(const TestFd &) = delete;
    int Get() const { return fd_; }
    void Reset(int fd = -1);
private:
    int fd_;
};

// 单一读取者的管道读取；信号中断后仍遵守最初的总期限。
bool ReadByteWithin(int fd, char &value,
    std::chrono::milliseconds timeout = std::chrono::seconds(3));

// 子进程必须在业务执行前 setpgid(0, 0)，使其后代与父测试进程隔离。
// Wait 保留退出进程供析构回收，确保清理进程组时组长 PID 尚未被复用。
class TestChild {
public:
    explicit TestChild(pid_t pid);
    ~TestChild();
    TestChild(const TestChild &) = delete;
    TestChild &operator=(const TestChild &) = delete;
    bool WaitSuccessful(std::chrono::milliseconds timeout = std::chrono::seconds(3));
private:
    pid_t pid_;
    bool groupReady_;
};
} // 命名空间 virtrust::test
