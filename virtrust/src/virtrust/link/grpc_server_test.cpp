/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "virtrust/base/str_utils.h"
#include "virtrust/link/grpc_server.h"

namespace virtrust {
// 独占持有测试描述符，断言提前返回时也会关闭；不提供复制或转交。
class TestFd {
public:
    explicit TestFd(int fd) : fd_(fd)
    {}
    ~TestFd()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    TestFd(const TestFd &) = delete;
    TestFd &operator=(const TestFd &) = delete;

private:
    int fd_;
};

// 显式关闭并检查写入结果，避免错误夹具被误当作业务失败。
bool WriteFixture(const std::string &path, const char *text)
{
    std::ofstream output(path);
    output << text;
    output.close();
    return output.good();
}

TEST(TestFdTest, EarlyReturnClosesDescriptor)
{
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    const auto leaveEarly = [fd] {
        TestFd owner(fd);
        return;
    };
    leaveEarly();
    errno = 0;
    EXPECT_EQ(close(fd), -1);
    EXPECT_EQ(errno, EBADF);
}

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
    void TearDown() override
    {
        if (!directory.empty()) {
            std::filesystem::remove_all(directory);
        }
    }
    std::string directory;
    LinkConfig config{};
};

TEST_F(GrpcServerTest, FailedStartCanBeStoppedAndDestroyedRepeatedly)
{
    config.udsPath = directory + "/missing/rpc.sock";
    EXPECT_EXIT(
        {
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
        },
        testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, ExistingRegularFileIsNeverDeleted)
{
    ASSERT_TRUE(WriteFixture(config.udsPath, "keep"));
    EXPECT_EXIT(
        {
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
        },
        testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, SymlinkIsNeverDeleted)
{
    ASSERT_EQ(symlink("missing-target", config.udsPath.c_str()), 0);
    EXPECT_EXIT(
        {
            bool ok;
            {
                GrpcServer server(config);
                ok = server.Start() == LinkRc::ERROR;
                server.Stop();
            }
            _exit(ok && std::filesystem::is_symlink(config.udsPath) &&
                          std::filesystem::read_symlink(config.udsPath) == "missing-target"
                      ? 0
                      : 1);
        },
        testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, DestructorStopsSuccessfulServerAndAllowsRestart)
{
    EXPECT_EXIT(
        {
            bool ok = true;
            for (int i = 0; i < 3; ++i) {
                GrpcServer server(config);
                ok = (server.Start() == LinkRc::OK) && ok;
                ok = (server.Start() == LinkRc::ERROR) && ok;
            }
            _exit(ok ? 0 : 1);
        },
        testing::ExitedWithCode(0), "");
}

TEST_F(GrpcServerTest, ActiveSocketIsNotRemovedByAnotherServer)
{
    const int socketFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    TestFd socketOwner(socketFd);
    ASSERT_GE(socketFd, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    config.udsPath.copy(address.sun_path, sizeof(address.sun_path) - 1);
    const int bound = bind(socketFd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    const int listening = bound == 0 ? listen(socketFd, 8) : -1;
    if (listening != 0) {
        FAIL() << "cannot create isolated socket";
    }
    struct stat before {};
    ASSERT_EQ(lstat(config.udsPath.c_str(), &before), 0);
    EXPECT_EXIT(
        {
            bool ok;
            {
                GrpcServer server(config);
                ok = server.Start() == LinkRc::ERROR;
                server.Stop();
            }
            struct stat after {};
            _exit(ok && lstat(config.udsPath.c_str(), &after) == 0 && before.st_ino == after.st_ino ? 0 : 1);
        },
        testing::ExitedWithCode(0), "");
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
    sockaddr_un address{};
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
    ASSERT_TRUE(WriteFixture(config.udsPath, "keep"));
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
    EXPECT_NE(server.LastError().find("type check"), std::string::npos);
    EXPECT_NE(server.LastError().find("tcp=127.0.0.1:0"), std::string::npos);
    EXPECT_NE(server.LastError().find("server_created=not_attempted"), std::string::npos);
    EXPECT_NE(server.LastError().find("tcp_result=not_attempted"), std::string::npos);
    EXPECT_NE(server.LastError().find("uds_result=not_attempted"), std::string::npos);
    EXPECT_TRUE(std::filesystem::is_regular_file(config.udsPath));
}

TEST_F(GrpcServerTest, StatFailureDiagnosticIncludesErrno)
{
    const std::string file = directory + "/not-directory";
    ASSERT_TRUE(WriteFixture(file, "keep"));
    config.udsPath = file + "/rpc.sock";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
    EXPECT_NE(server.LastError().find("Initial UDS lstat"), std::string::npos);
    EXPECT_NE(server.LastError().find("errno=" + std::to_string(ENOTDIR)), std::string::npos);
}
// 不完整的 TLS 配置不能静默回退到明文监听。
TEST_F(GrpcServerTest, PartialTlsConfigurationIsRejected)
{
    for (unsigned mask = 1; mask < 7; ++mask) {
        config.skPath = (mask & 1) ? directory + "/key" : "";
        config.certPath = (mask & 2) ? directory + "/cert" : "";
        config.caPath = (mask & 4) ? directory + "/ca" : "";
        GrpcServer server(config);
        EXPECT_EQ(server.Start(), LinkRc::ERROR) << mask;
        EXPECT_NE(server.LastError().find("Incomplete TLS configuration"), std::string::npos);
        EXPECT_NE(server.LastError().find("missing="), std::string::npos);
        server.Stop();
    }
}

TEST_F(GrpcServerTest, ListenerFailureReportsKnownFacts)
{
    config.udsPath = directory + "/missing/rpc.sock";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    const auto error = server.LastError();
    EXPECT_NE(error.find("BuildAndStart"), std::string::npos);
    EXPECT_NE(error.find("tcp=127.0.0.1:0"), std::string::npos);
    EXPECT_NE(error.find(config.udsPath), std::string::npos);
    EXPECT_NE(error.find("server_created="), std::string::npos);
    EXPECT_NE(error.find("tcp_result="), std::string::npos);
    EXPECT_NE(error.find("uds_result="), std::string::npos);
}

// 使用本机构建生成的证书，不在仓库中添加任何私钥材料。
TEST_F(GrpcServerTest, CompleteTlsConfigurationStartsWithoutPlaintextFallback)
{
    const std::string certRoot = VIRTRUST_TEST_CERT_DIR;
    config.skPath = certRoot + "/server/sk.pem";
    config.certPath = certRoot + "/server/cert.pem";
    config.caPath = certRoot + "/ca/cert.pem";
    ASSERT_FALSE(ReadFile(config.skPath).empty());
    ASSERT_FALSE(ReadFile(config.certPath).empty());
    ASSERT_FALSE(ReadFile(config.caPath).empty());
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::OK) << server.LastError();
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}

TEST_F(GrpcServerTest, NonemptyInvalidCertificatesFailWithoutDowngrade)
{
    config.skPath = directory + "/key";
    config.certPath = directory + "/cert";
    config.caPath = directory + "/ca";
    ASSERT_TRUE(WriteFixture(config.skPath, "invalid-key"));
    ASSERT_TRUE(WriteFixture(config.certPath, "invalid-cert"));
    ASSERT_TRUE(WriteFixture(config.caPath, "invalid-ca"));
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("BuildAndStart"), std::string::npos);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
}
} // 命名空间 virtrust
