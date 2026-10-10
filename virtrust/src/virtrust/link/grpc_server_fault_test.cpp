/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>

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
    GrpcServer server(config);
    Peer::Ops(server).build = [](grpc::ServerBuilder &) -> std::unique_ptr<grpc::Server> { throw std::bad_alloc(); };
    Peer::Ops(server).diagnostic = [](std::string &, const std::string &) { throw std::bad_alloc(); };
    Peer::Ops(server).log = [](const char *, bool) { throw std::bad_alloc(); };
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    ExpectReleased(server);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
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
    GrpcServer server(config);
    Peer::Ops(server).destroy = [&](std::unique_ptr<grpc::Server> &transport) {
        EXPECT_TRUE(Peer::HasService(server));
        EXPECT_FALSE(Peer::HasThread(server));
        transport.reset();
        ++destroyed;
    };
    for (int attempt = 0; attempt < 2; ++attempt) {
        ASSERT_EQ(server.Start(), LinkRc::OK);
        EXPECT_EQ(server.Start(), LinkRc::ERROR);
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        ExpectReleased(server);
    }
    EXPECT_EQ(destroyed, 2);
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
    for (int fault = 0; fault < 3; ++fault) {
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
            *info = original;
            if (fault == 0 && fail.load()) {
                ++info->st_ino;
            }
            return 0;
        };
        Peer::Ops(server).unlink = [&](const char *) {
            ++unlinks;
            if (fault == 2 && fail.load()) {
                errno = EACCES;
                return -1;
            }
            return 0;
        };
        ASSERT_EQ(server.Start(), LinkRc::OK);
        cleaning = true;
        EXPECT_EQ(server.Stop(), StopResult::PathCleanupFailed);
        EXPECT_TRUE(Peer::HasIdentity(server));
        ExpectReleased(server);
        EXPECT_EQ(unlinks, fault == 2 ? 1 : 0);
        fail = false;
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        EXPECT_FALSE(Peer::HasIdentity(server));
        EXPECT_EQ(unlinks, fault == 2 ? 2 : 1);
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
    }
}

TEST_F(GrpcServerFaultTest, DestructorTerminatesWhenShutdownCannotSafelyComplete)
{
    EXPECT_DEATH(
        {
            GrpcServer server(config);
            Peer::Ops(server).shutdown = [](grpc::Server &) { throw std::runtime_error("shutdown failed"); };
            if (server.Start() != LinkRc::OK) {
                _exit(0);
            }
        },
        "");
}
} // 匿名命名空间
} // 命名空间 virtrust
