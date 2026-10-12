/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <stdexcept>
#include <vector>

#include "virtrust/link/grpc_server_test_peer.h"

namespace virtrust {
namespace {
using Peer = GrpcServerTestPeer;

// 提前返回时先关闭故障，后析构被保护对象。
TEST(TestFaultResetTest, ClearsFailureBeforeProtectedObjectDestruction)
{
    bool fail = true;
    bool cleanAtDestruction = false;
    const auto leaveEarly = [&] {
        struct Probe {
            bool &fail;
            bool &clean;
            ~Probe()
            {
                clean = !fail;
            }
        } probe{fail, cleanAtDestruction};
        TestFaultReset<bool> reset(fail);
        return;
    };
    leaveEarly();
    EXPECT_TRUE(cleanAtDestruction);
}

class EmptyError : public std::exception {
public:
    const char *what() const noexcept override
    {
        return "";
    }
};

class GrpcServerFaultTest : public testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-fault-ut.XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        directory = created;
        config.ip = "127.0.0.1";
        config.port = 0;
        config.udsPath = directory + "/rpc.sock";
    }
    void TearDown() override
    {
        if (!directory.empty()) {
            std::filesystem::remove_all(directory);
        }
    }
    void ExpectReleased(GrpcServer &server)
    {
        EXPECT_FALSE(Peer::HasThread(server));
        EXPECT_FALSE(Peer::HasThreadObject(server));
        EXPECT_FALSE(Peer::HasServer(server));
        EXPECT_FALSE(Peer::HasService(server));
    }
    LinkConfig config{};
    std::string directory;
};

TEST_F(GrpcServerFaultTest, EmptyExceptionMessageStillFailsAndReleasesResources)
{
    GrpcServer server(config);
    Peer::Ops(server).build = [](grpc::ServerBuilder &) -> std::unique_ptr<grpc::Server> { throw EmptyError(); };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    ExpectReleased(server);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}

// 按系统结构实际容量构造边界；非法路径必须在系统探测和创建线程之前拒绝。
TEST_F(GrpcServerFaultTest, InvalidSocketPathsFailBeforeExternalOperations)
{
    sockaddr_un address{};
    const auto capacity = sizeof(address.sun_path);
    const std::vector<std::string> paths{"", "relative/rpc.sock", "/" + std::string(capacity - 1, 'x'),
                                         "/" + std::string(capacity, 'x')};
    for (const auto &path : paths) {
        SCOPED_TRACE(path.size());
        int stats = 0, unlinks = 0, starts = 0;
        std::atomic<int> builds{0};
        config.udsPath = path;
        GrpcServer server(config);
        const auto start = Peer::Ops(server).start;
        Peer::Ops(server).stat = [&](const char *name, struct stat *info) {
            ++stats;
            return ::lstat(name, info);
        };
        Peer::Ops(server).unlink = [&](const char *name) {
            ++unlinks;
            return ::unlink(name);
        };
        Peer::Ops(server).start = [&](GrpcServer &owner, std::promise<Peer::StartupResult> ready) {
            ++starts;
            return start(owner, std::move(ready));
        };
        Peer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
            ++builds;
            return builder.BuildAndStart();
        };
        EXPECT_EQ(server.Start(), LinkRc::ERROR);
        EXPECT_NE(server.LastError().find("Invalid UDS path"), std::string::npos);
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        EXPECT_EQ(stats, 0);
        EXPECT_EQ(unlinks, 0);
        EXPECT_EQ(starts, 0);
        EXPECT_EQ(builds.load(), 0);
        ExpectReleased(server);
    }
}

// sun_path 需为结尾空字符保留一字节，容量减一是本接口接受的最大路径长度。
TEST_F(GrpcServerFaultTest, MaximumAcceptedSocketPathStartsAndCleansUp)
{
    sockaddr_un address{};
    const auto length = sizeof(address.sun_path) - 1;
    ASSERT_LT(directory.size() + 1, length);
    config.udsPath = directory + "/" + std::string(length - directory.size() - 1, 'x');
    ASSERT_EQ(config.udsPath.size(), length);
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::OK) << server.LastError();
    EXPECT_TRUE(Peer::HasIdentity(server));
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_FALSE(Peer::HasIdentity(server));
    ExpectReleased(server);
    EXPECT_FALSE(std::filesystem::exists(config.udsPath));
}

TEST_F(GrpcServerFaultTest, PrecheckExceptionDoesNotEscapeStart)
{
    GrpcServer server(config);
    Peer::Ops(server).stat = [](const char *, struct stat *) -> int { throw EmptyError(); };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, ThreadCreationExceptionCannotReportSuccess)
{
    GrpcServer server(config);
    Peer::Ops(server).start = [](GrpcServer &, std::promise<Peer::StartupResult>) -> std::unique_ptr<std::thread> {
        throw EmptyError();
    };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("Thread creation"), std::string::npos);
    EXPECT_NE(server.LastError().find("tcp_result=not_attempted"), std::string::npos);
    EXPECT_NE(server.LastError().find("uds_result=not_attempted"), std::string::npos);
    ExpectReleased(server);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}

TEST_F(GrpcServerFaultTest, DiagnosticAndLogAllocationFailuresDoNotPreventCleanup)
{
    std::atomic<int> builds{0}, diagnostics{0}, logs{0};
    GrpcServer server(config);
    Peer::Ops(server).build = [&](grpc::ServerBuilder &) -> std::unique_ptr<grpc::Server> {
        ++builds;
        throw std::bad_alloc();
    };
    Peer::Ops(server).diagnostic = [&](std::string &, const std::string &) {
        ++diagnostics;
        throw std::bad_alloc();
    };
    Peer::Ops(server).log = [&](const char *, bool) {
        ++logs;
        throw std::bad_alloc();
    };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    ExpectReleased(server);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_EQ(builds.load(), 1);
    EXPECT_GT(diagnostics.load(), 0);
    EXPECT_GT(logs.load(), 0);
}

// 构建回调返回空对象时，监听输出仍是初始零值，不能只检查字段是否存在。
TEST_F(GrpcServerFaultTest, NullBuildReportsExactListenerFacts)
{
    int builds = 0;
    GrpcServer server(config);
    Peer::Ops(server).build = [&](grpc::ServerBuilder &) -> std::unique_ptr<grpc::Server> {
        ++builds;
        return nullptr;
    };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    const auto detail = server.LastError();
    EXPECT_NE(detail.find("BuildAndStart"), std::string::npos);
    EXPECT_NE(detail.find("server_created=false, tcp_result=0, uds_result=0"), std::string::npos);
    EXPECT_NE(detail.find("tcp=127.0.0.1:0"), std::string::npos);
    EXPECT_NE(detail.find("uds=" + config.udsPath), std::string::npos);
    EXPECT_EQ(builds, 1);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, FailedPublishBreaksPromiseWithoutSecondNotification)
{
    std::atomic<int> notifications{0};
    GrpcServer server(config);
    Peer::Ops(server).publish = [&](std::promise<Peer::StartupResult> &, Peer::StartupResult) {
        ++notifications;
        throw std::runtime_error("publish failed");
    };
    Peer::Ops(server).log = [](const char *, bool) { throw std::bad_alloc(); };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_EQ(notifications.load(), 1);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, PublishExceptionAfterDeliveryNeverNotifiesTwice)
{
    std::atomic<int> notifications{0};
    GrpcServer server(config);
    Peer::Ops(server).publish = [&](std::promise<Peer::StartupResult> &ready, Peer::StartupResult result) {
        ++notifications;
        ready.set_value(std::move(result));
        throw std::runtime_error("publish failed after delivery");
    };
    // 通知已送达后，启动结果与工作线程故障分开报告。
    EXPECT_EQ(server.Start(), LinkRc::OK);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_EQ(notifications.load(), 1);
    EXPECT_TRUE(server.HasRuntimeFailure());
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, WaitExceptionSetsFaultEvenWhenDiagnosticAndLogThrow)
{
    GrpcServer server(config);
    Peer::Ops(server).wait = [](grpc::Server &) { throw std::runtime_error("wait failed"); };
    Peer::Ops(server).diagnostic = [](std::string &, const std::string &) { throw std::bad_alloc(); };
    Peer::Ops(server).log = [](const char *, bool) { throw std::bad_alloc(); };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    EXPECT_TRUE(Peer::HasService(server));
    EXPECT_TRUE(Peer::HasServer(server));
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_TRUE(server.HasRuntimeFailure());
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, ShutdownFailureRetainsResourcesUntilRetry)
{
    std::atomic<bool> fail{true};
    GrpcServer server(config);
    TestFaultReset<std::atomic<bool>> reset(fail);
    Peer::Ops(server).shutdown = [&](grpc::Server &transport) {
        if (fail.load()) {
            throw std::runtime_error("shutdown failed");
        }
        transport.Shutdown();
    };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    EXPECT_EQ(server.Stop(), StopResult::Incomplete);
    EXPECT_TRUE(Peer::HasService(server));
    EXPECT_TRUE(Peer::HasServer(server));
    EXPECT_TRUE(Peer::HasThread(server));
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    fail = false;
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, JoinFailureRetainsResourcesUntilRetry)
{
    std::atomic<bool> fail{true};
    GrpcServer server(config);
    TestFaultReset<std::atomic<bool>> reset(fail);
    Peer::Ops(server).join = [&](std::thread &thread) {
        if (fail.load()) {
            throw std::runtime_error("join failed");
        }
        thread.join();
    };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    EXPECT_EQ(server.Stop(), StopResult::Incomplete);
    EXPECT_TRUE(Peer::HasService(server));
    EXPECT_TRUE(Peer::HasServer(server));
    EXPECT_TRUE(Peer::HasThread(server));
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    fail = false;
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, ServerDestructionOccursAfterJoinAndBeforeServiceDestruction)
{
    int destroyed = 0;
    // 回调仅由停止调用线程执行；事件记录的生命周期覆盖 server 析构。
    std::vector<std::string> events;
    GrpcServer server(config);
    Peer::Ops(server).shutdown = [&](grpc::Server &transport) {
        transport.Shutdown();
        events.emplace_back("shutdown_completed");
    };
    Peer::Ops(server).join = [&](std::thread &thread) {
        EXPECT_TRUE(thread.joinable());
        thread.join();
        EXPECT_FALSE(thread.joinable());
        events.emplace_back("join_completed");
    };
    Peer::Ops(server).destroy = [&](std::unique_ptr<grpc::Server> &transport) {
        EXPECT_TRUE(Peer::HasService(server));
        EXPECT_FALSE(Peer::HasThread(server));
        EXPECT_FALSE(Peer::HasThreadObject(server));
        events.emplace_back("server_destroy_begin");
        transport.reset();
        EXPECT_TRUE(Peer::HasService(server));
        events.emplace_back("server_destroy_end");
        ++destroyed;
    };
    for (int attempt = 0; attempt < 2; ++attempt) {
        events.clear();
        ASSERT_EQ(server.Start(), LinkRc::OK);
        EXPECT_EQ(server.Start(), LinkRc::ERROR);
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        ExpectReleased(server);
        EXPECT_EQ(events, (std::vector<std::string>{"shutdown_completed", "join_completed", "server_destroy_begin",
                                                    "server_destroy_end"}));
    }
    EXPECT_EQ(destroyed, 2);
}

// 在构建入口暂停启动，停止线程先探测生命周期锁再发起停止；不使用 sleep 推测进度。
// 探针与 Stop 加锁之间仍有调度窗口，不声称观察到了 Stop 内部的锁等待队列。
// 同步等待有界，第三方关闭及线程回收若永久阻塞仍由 CTest 进程超时兜底。
TEST_F(GrpcServerFaultTest, StopScheduledWhileBuildPausedReclaimsAllResources)
{
    using namespace std::chrono_literals;
    std::promise<void> entered;
    auto enteredFuture = entered.get_future();
    std::promise<void> release;
    auto releaseFuture = release.get_future().share();
    // 仅交接锁探针结果，不表示 Stop 已经进入锁等待。
    std::promise<bool> lockProbeResult;
    auto lockProbeFuture = lockProbeResult.get_future();
    std::atomic<bool> gateTimedOut{false};
    std::atomic<int> shutdowns{0};
    GrpcServer server(config);
    Peer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
        entered.set_value();
        if (releaseFuture.wait_for(3s) != std::future_status::ready) {
            gateTimedOut = true;
            throw std::runtime_error("Startup test gate timed out");
        }
        return builder.BuildAndStart();
    };
    Peer::Ops(server).shutdown = [&](grpc::Server &transport) {
        ++shutdowns;
        transport.Shutdown();
    };
    auto starting = std::async(std::launch::async, [&] { return server.Start(); });
    // 即使此断言失败，构建门也会自行超时；future 析构等待调用线程退出。
    ASSERT_EQ(enteredFuture.wait_for(3s), std::future_status::ready);
    auto stopping = std::async(std::launch::async, [&] {
        lockProbeResult.set_value(Peer::CanAcquireLifecycleLock(server));
        return server.Stop();
    });
    const auto probeStatus = lockProbeFuture.wait_for(3s);
    EXPECT_EQ(probeStatus, std::future_status::ready);
    if (probeStatus == std::future_status::ready) {
        EXPECT_FALSE(lockProbeFuture.get());
    }
    EXPECT_EQ(shutdowns.load(), 0);
    release.set_value();
    ASSERT_EQ(starting.wait_for(3s), std::future_status::ready);
    EXPECT_EQ(starting.get(), LinkRc::OK);
    ASSERT_EQ(stopping.wait_for(3s), std::future_status::ready);
    EXPECT_EQ(stopping.get(), StopResult::Stopped);
    EXPECT_FALSE(gateTimedOut.load());
    EXPECT_EQ(shutdowns.load(), 1);
    ExpectReleased(server);
    EXPECT_FALSE(Peer::HasIdentity(server));
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}

TEST_F(GrpcServerFaultTest, InvalidPostBuildSocketAlwaysFailsStartupWithoutWrapperUnlink)
{
    // 各次独立启动分别注入缺失、类型、属主和系统调用失败，不假定 gRPC 自身清理行为。
    for (int fault = 0; fault < 4; ++fault) {
        SCOPED_TRACE(fault);
        std::atomic<bool> built{false};
        int unlinks = 0;
        int destroyed = 0;
        GrpcServer server(config);
        Peer::Ops(server).destroy = [&](std::unique_ptr<grpc::Server> &transport) {
            EXPECT_TRUE(Peer::HasService(server));
            EXPECT_FALSE(Peer::HasThread(server));
            transport.reset();
            ++destroyed;
        };
        Peer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
            auto transport = builder.BuildAndStart();
            built = true;
            return transport;
        };
        Peer::Ops(server).stat = [&](const char *path, struct stat *info) {
            if (!built.load()) {
                return ::lstat(path, info);
            }
            if (fault == 0 || fault == 3) {
                errno = fault == 0 ? ENOENT : EACCES;
                return -1;
            }
            const int result = ::lstat(path, info);
            if (result == 0) {
                if (fault == 1) {
                    info->st_mode = S_IFREG | 0600;
                } else {
                    info->st_uid = geteuid() + 1;
                }
            }
            return result;
        };
        Peer::Ops(server).unlink = [&](const char *) {
            ++unlinks;
            return 0;
        };
        EXPECT_EQ(server.Start(), LinkRc::ERROR);
        EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
        EXPECT_FALSE(Peer::HasIdentity(server));
        EXPECT_EQ(unlinks, 0);
        EXPECT_EQ(destroyed, 1);
        ExpectReleased(server);
    }
}

TEST_F(GrpcServerFaultTest, CleanupMissingPathCountsAsStopped)
{
    std::atomic<bool> cleaning{false};
    GrpcServer server(config);
    Peer::Ops(server).stat = [&](const char *path, struct stat *info) {
        if (cleaning.load()) {
            errno = ENOENT;
            return -1;
        }
        return ::lstat(path, info);
    };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    cleaning = true;
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_FALSE(Peer::HasIdentity(server));
    ExpectReleased(server);
}

// 模拟身份检查通过后路径消失：unlink 的 ENOENT 应容错并清除记录，不再次删除。
TEST_F(GrpcServerFaultTest, CleanupUnlinkMissingPathClearsIdentityWithoutRetry)
{
    std::atomic<bool> cleaning{false};
    struct stat original {};
    int unlinks = 0;
    GrpcServer server(config);
    Peer::Ops(server).stat = [&](const char *path, struct stat *info) {
        if (cleaning.load()) {
            *info = original;
            return 0;
        }
        const int result = ::lstat(path, info);
        if (result == 0) {
            original = *info;
        }
        return result;
    };
    Peer::Ops(server).unlink = [&](const char *) {
        ++unlinks;
        errno = ENOENT;
        return -1;
    };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    EXPECT_TRUE(Peer::HasIdentity(server));
    cleaning = true;
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_EQ(unlinks, 1);
    EXPECT_FALSE(Peer::HasIdentity(server));
    ExpectReleased(server);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_EQ(unlinks, 1);
}

TEST_F(GrpcServerFaultTest, StartupReasonSurvivesCleanupFailure)
{
    bool failShutdown = true;
    std::atomic<bool> built{false};
    GrpcServer server(config);
    TestFaultReset<bool> reset(failShutdown);
    // 先实际建立监听，再在必要的路径身份校验阶段失败。
    Peer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
        auto transport = builder.BuildAndStart();
        built = true;
        return transport;
    };
    Peer::Ops(server).stat = [&](const char *path, struct stat *info) {
        if (built.load()) {
            errno = EACCES;
            return -1;
        }
        return ::lstat(path, info);
    };
    Peer::Ops(server).shutdown = [&](grpc::Server &transport) {
        if (failShutdown) {
            throw std::runtime_error("injected shutdown failure");
        }
        transport.Shutdown();
    };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("Post-start UDS lstat failed"), std::string::npos);
    EXPECT_NE(server.LastError().find("Server Shutdown failed"), std::string::npos);
    EXPECT_TRUE(Peer::HasService(server));
    failShutdown = false;
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    ExpectReleased(server);
}

TEST_F(GrpcServerFaultTest, ActualReplacementAfterServerDestructionIsPreserved)
{
    GrpcServer server(config);
    Peer::Ops(server).destroy = [&](std::unique_ptr<grpc::Server> &transport) {
        transport.reset();
        // 在 gRPC 自身清理之后实际替换路径，验证封装层不会删除新文件。
        const int removed = ::unlink(config.udsPath.c_str());
        ASSERT_TRUE(removed == 0 || errno == ENOENT);
        std::ofstream output(config.udsPath);
        output << "replacement";
        output.close();
        ASSERT_TRUE(output.good());
    };
    ASSERT_EQ(server.Start(), LinkRc::OK);
    EXPECT_EQ(server.Stop(), StopResult::PathCleanupFailed);
    EXPECT_EQ(server.Stop(), StopResult::PathCleanupFailed);
    std::ifstream input(config.udsPath);
    std::string value;
    input >> value;
    EXPECT_EQ(value, "replacement");
    EXPECT_EQ(::unlink(config.udsPath.c_str()), 0);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}

TEST_F(GrpcServerFaultTest, CleanupFailuresRetainOriginalIdentityForRetry)
{
    // gRPC 可能已移除真实路径；保留启动快照，隔离验证封装层重试语义。
    for (int fault = 0; fault < 6; ++fault) {
        SCOPED_TRACE(fault);
        std::atomic<bool> cleaning{false};
        std::atomic<bool> fail{true};
        struct stat original {};
        int unlinks = 0;
        GrpcServer server(config);
        Peer::Ops(server).stat = [&](const char *path, struct stat *info) {
            if (!cleaning.load()) {
                const int result = ::lstat(path, info);
                if (result == 0) {
                    original = *info;
                }
                return result;
            }
            if (fault == 1 && fail.load()) {
                errno = EACCES;
                return -1;
            }
            if (fault == 4 && fail.load()) {
                throw std::runtime_error("Injected cleanup stat exception");
            }
            *info = original;
            if (fault == 0 && fail.load()) {
                ++info->st_ino;
            }
            if (fault == 3 && fail.load()) {
                info->st_dev ^= 1;
            }
            return 0;
        };
        Peer::Ops(server).unlink = [&](const char *) {
            ++unlinks;
            if (fault == 2 && fail.load()) {
                errno = EACCES;
                return -1;
            }
            if (fault == 5 && fail.load()) {
                throw std::runtime_error("Injected cleanup unlink exception");
            }
            return 0;
        };
        ASSERT_EQ(server.Start(), LinkRc::OK);
        cleaning = true;
        EXPECT_EQ(server.Stop(), StopResult::PathCleanupFailed);
        const char *expectedStage = fault == 1                 ? "UDS cleanup lstat failed"
                                    : fault == 2               ? "UDS cleanup unlink failed"
                                    : fault == 4 || fault == 5 ? "Exception during UDS cleanup"
                                                               : "UDS cleanup identity mismatch";
        EXPECT_NE(server.LastError().find(expectedStage), std::string::npos);
        EXPECT_TRUE(Peer::HasIdentity(server));
        ExpectReleased(server);
        EXPECT_EQ(unlinks, fault == 2 || fault == 5 ? 1 : 0);
        fail = false;
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        EXPECT_FALSE(Peer::HasIdentity(server));
        EXPECT_EQ(unlinks, fault == 2 || fault == 5 ? 2 : 1);
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
    }
}

TEST_F(GrpcServerFaultTest, DestructorTerminatesWhenShutdownCannotSafelyComplete)
{
    EXPECT_EXIT(
        {
            GrpcServer server(config);
            Peer::Ops(server).shutdown = [](grpc::Server &) { throw std::runtime_error("shutdown failed"); };
            if (server.Start() != LinkRc::OK) {
                _exit(0);
            }
            // 先确认具体失败条件，再安装子进程专用终止处理器，区别于一般异常崩溃。
            if (server.Stop() != StopResult::Incomplete) {
                _exit(0);
            }
            std::set_terminate([] {
                const char marker[] = "Expected incomplete cleanup termination\n";
                const auto written = ::write(STDERR_FILENO, marker, sizeof(marker) - 1);
                _exit(written == static_cast<ssize_t>(sizeof(marker) - 1) ? 87 : 88);
            });
        },
        testing::ExitedWithCode(87), "Expected incomplete cleanup termination");
}
} // 匿名命名空间
} // 命名空间 virtrust
