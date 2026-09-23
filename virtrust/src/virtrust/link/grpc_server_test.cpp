/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include "virtrust/link/grpc_server.h"
#include <gtest/gtest.h>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace virtrust {
// 独立目录与临时端口，不接触真实服务；子进程隔离旧实现 terminate 的故障。
class GrpcServerTest : public testing::Test {
protected:
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-server-ut.XXXXXX";
        const char *created = mkdtemp(pattern);
        ASSERT_NE(created, nullptr);
        directory = created;
        config.ip = "127.0.0.1";
        config.port = 0;
        config.udsPath = directory + "/rpc.sock";
    }
    void TearDown() override { if (!directory.empty()) { std::filesystem::remove_all(directory); } }
    std::string directory;
    LinkConfig config {};
};

TEST_F(GrpcServerTest, FailedStartCanBeStoppedAndDestroyedRepeatedly)
{
    config.udsPath = directory + "/missing/rpc.sock";
    EXPECT_EXIT({
        bool ok = true;
        {
            GrpcServer server(config);
            for (int i = 0; i < 3; ++i) {
                ok = (server.Start() == LinkRc::ERROR) && ok;
                server.Stop();
                server.Stop();
            }
        }
        _exit(ok ? 0 : 1);
    }, testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, ExistingRegularFileIsNeverDeleted)
{
    std::ofstream(config.udsPath) << "keep";
    EXPECT_EXIT({
        bool ok;
        {
            GrpcServer server(config);
            ok = server.Start() == LinkRc::ERROR;
            server.Stop();
        }
        std::ifstream input(config.udsPath);
        std::string text;
        input >> text;
        _exit(ok && text == "keep" ? 0 : 1);
    }, testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, SymlinkIsNeverDeleted)
{
    ASSERT_EQ(symlink("missing-target", config.udsPath.c_str()), 0);
    EXPECT_EXIT({
        bool ok;
        {
            GrpcServer server(config);
            ok = server.Start() == LinkRc::ERROR;
            server.Stop();
        }
        _exit(ok && std::filesystem::is_symlink(config.udsPath) ? 0 : 1);
    }, testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, DestructorStopsSuccessfulServerAndAllowsRestart)
{
    EXPECT_EXIT({
        bool ok = true;
        for (int i = 0; i < 3; ++i) {
            GrpcServer server(config);
            ok = (server.Start() == LinkRc::OK) && ok;
            ok = (server.Start() == LinkRc::ERROR) && ok;
        }
        _exit(ok ? 0 : 1);
    }, testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, ActiveSocketIsNotRemovedByAnotherServer)
{
    const int socketFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(socketFd, 0);
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    config.udsPath.copy(address.sun_path, sizeof(address.sun_path) - 1);
    const int bound = bind(socketFd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    const int listening = bound == 0 ? listen(socketFd, 8) : -1;
    if (listening != 0) { close(socketFd); FAIL() << "cannot create isolated socket"; }
    struct stat before {};
    ASSERT_EQ(lstat(config.udsPath.c_str(), &before), 0);
    EXPECT_EXIT({
        bool ok;
        {
            GrpcServer server(config);
            ok = server.Start() == LinkRc::ERROR;
            server.Stop();
        }
        struct stat after {};
        _exit(ok && lstat(config.udsPath.c_str(), &after) == 0 && before.st_ino == after.st_ino ? 0 : 1);
    }, testing::ExitedWithCode(0), "");
    close(socketFd);
}
// 同一对象反复 Start/Stop，验证线程和服务指针均已回收，诊断也可再次使用。
TEST_F(GrpcServerTest, SameObjectCanRestartAndReportFailures)
{
    GrpcServer server(config);
    server.Stop();
    for (int i = 0; i < 3; ++i) {
        ASSERT_EQ(server.Start(), LinkRc::OK) << server.LastError();
        EXPECT_TRUE(server.LastError().empty());
        EXPECT_EQ(server.Start(), LinkRc::ERROR);
        EXPECT_FALSE(server.LastError().empty());
        server.Stop();
        server.Stop();
    }
}

TEST_F(GrpcServerTest, StaleSocketCanBeReplaced)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    config.udsPath.copy(address.sun_path, sizeof(address.sun_path) - 1);
    int result = bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    close(fd);
    ASSERT_EQ(result, 0);
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::OK) << server.LastError();
    server.Stop();
    EXPECT_FALSE(std::filesystem::exists(config.udsPath));
}

TEST_F(GrpcServerTest, InvalidTlsReturnsDiagnosticWithoutLeavingThread)
{
    config.caPath = directory + "/absent-ca";
    config.certPath = directory + "/absent-cert";
    config.skPath = directory + "/absent-key";
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_FALSE(server.LastError().empty());
    server.Stop();
}
// 诊断必须指向实际路径和检查阶段，而非只返回无法定位的泛化错误。
TEST_F(GrpcServerTest, RegularFileDiagnosticIncludesPathAndStage)
{
    std::ofstream(config.udsPath) << "keep";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
    EXPECT_NE(server.LastError().find("type check"), std::string::npos);
    EXPECT_TRUE(std::filesystem::is_regular_file(config.udsPath));
}

TEST_F(GrpcServerTest, StatFailureDiagnosticIncludesErrno)
{
    const std::string file = directory + "/not-directory";
    std::ofstream(file) << "keep";
    config.udsPath = file + "/rpc.sock";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
    EXPECT_NE(server.LastError().find("Initial UDS lstat"), std::string::npos);
    EXPECT_NE(server.LastError().find("errno=" + std::to_string(ENOTDIR)), std::string::npos);
}
} // 命名空间 virtrust
