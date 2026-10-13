/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "virtrust/base/str_utils.h"
#include "virtrust/link/grpc_server.h"
#include "virtrust/link/grpc_server_test_peer.h"

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

// 不安全父目录必须在本层 Socket 查询/删除与线程创建/服务构建前拒绝，不自动修改权限。
TEST_F(GrpcServerTest, UnsafeParentRejectedBeforeSocketOperations)
{
    for (mode_t mode : {0755, 0770, 0777}) {
        SCOPED_TRACE(mode);
        ASSERT_EQ(chmod(directory.c_str(), mode), 0);
        int stats = 0;
        int unlinks = 0;
        std::atomic<int> starts{0};
        std::atomic<int> builds{0};
        {
            GrpcServer server(config);
            auto &ops = GrpcServerTestPeer::Ops(server);
            ops.stat = [&](const char *path, struct stat *info) {
                ++stats;
                return lstat(path, info);
            };
            ops.unlink = [&](const char *path) {
                ++unlinks;
                return unlink(path);
            };
            // 保留真实操作，仅统计入口调用；计数器活到 server 析构之后。
            const auto start = ops.start;
            ops.start = [&, start](GrpcServer &owner, std::promise<GrpcServerTestPeer::StartupResult> ready) {
                ++starts;
                return start(owner, std::move(ready));
            };
            ops.build = [&](grpc::ServerBuilder &builder) {
                ++builds;
                return builder.BuildAndStart();
            };
            EXPECT_EQ(server.Start(), LinkRc::ERROR);
            EXPECT_NE(server.LastError().find("UDS parent"), std::string::npos);
            EXPECT_EQ(stats, 0);
            EXPECT_EQ(unlinks, 0);
            EXPECT_EQ(starts.load(), 0);
            EXPECT_EQ(builds.load(), 0);
            EXPECT_FALSE(GrpcServerTestPeer::HasThreadObject(server));
            struct stat info {};
            ASSERT_EQ(stat(directory.c_str(), &info), 0);
            EXPECT_EQ(info.st_mode & 07777, mode);
            EXPECT_EQ(server.Stop(), StopResult::Stopped);
        }
        // 覆盖显式 Stop 以及析构，不能只观察 Start 返回时刻。
        EXPECT_EQ(stats, 0);
        EXPECT_EQ(unlinks, 0);
        EXPECT_EQ(starts.load(), 0);
        EXPECT_EQ(builds.load(), 0);
    }
    ASSERT_EQ(chmod(directory.c_str(), 0700), 0);
}

// 即使符号链接指向安全目录，也不允许通过它访问生产端点。
TEST_F(GrpcServerTest, SymlinkParentRejected)
{
    const auto alias = directory + "/alias";
    ASSERT_EQ(symlink(directory.c_str(), alias.c_str()), 0);
    config.udsPath = alias + "/rpc.sock";
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("UDS parent"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(directory + "/rpc.sock"));
}

// 末级 0700 不能抵消上级目录被其他用户替换的风险。
TEST_F(GrpcServerTest, WritableAncestorRejected)
{
    const auto parent = directory + "/private";
    ASSERT_EQ(mkdir(parent.c_str(), 0700), 0);
    ASSERT_EQ(chmod(parent.c_str(), 0700), 0);
    struct stat info {};
    ASSERT_EQ(stat(parent.c_str(), &info), 0);
    ASSERT_EQ(info.st_uid, geteuid());
    ASSERT_EQ(info.st_mode & 07777, static_cast<mode_t>(0700));
    ASSERT_EQ(chmod(directory.c_str(), 0777), 0);
    config.udsPath = parent + "/rpc.sock";
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("untrusted ancestor"), std::string::npos);
    ASSERT_EQ(chmod(directory.c_str(), 0700), 0);
}

// 实际属主检查需要特权；普通用户测试明确跳过，不能当作已完成权限验收。
TEST_F(GrpcServerTest, ForeignParentOwnerRejected)
{
    if (geteuid() != 0) {
        GTEST_SKIP() << "Root is required to change directory ownership";
    }
    const auto parent = directory + "/foreign";
    ASSERT_EQ(mkdir(parent.c_str(), 0700), 0);
    // 只改变属主，不引入属组差异；显式设置并核验权限以排除 umask 影响。
    ASSERT_EQ(chown(parent.c_str(), 1, static_cast<gid_t>(-1)), 0);
    ASSERT_EQ(chmod(parent.c_str(), 0700), 0);
    struct stat info {};
    ASSERT_EQ(stat(parent.c_str(), &info), 0);
    ASSERT_EQ(info.st_uid, 1U);
    ASSERT_EQ(info.st_mode & 07777, static_cast<mode_t>(0700));
    config.udsPath = parent + "/rpc.sock";
    GrpcServer server(config);
    EXPECT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find("owned by the effective UID"), std::string::npos);
}

// 运行后目录权限变化时先回收资源，拒绝本层 Socket lstat/unlink，并保留身份供修复后重试。
// 父目录检查仍访问文件系统，gRPC 销毁阶段的内部清理也不在本层计数范围内。
TEST_F(GrpcServerTest, UnsafeParentPreventsCleanupAndAllowsRetryAfterRepair)
{
    int stats = 0;
    int unlinks = 0;
    GrpcServer server(config);
    auto &ops = GrpcServerTestPeer::Ops(server);
    ops.stat = [&](const char *path, struct stat *info) {
        ++stats;
        return lstat(path, info);
    };
    ops.unlink = [&](const char *path) {
        ++unlinks;
        return unlink(path);
    };
    ASSERT_EQ(server.Start(), LinkRc::OK) << server.LastError();
    // 回调在启动前安装，启动成功后重置计数，后续只观察停止阶段。
    stats = 0;
    unlinks = 0;
    ASSERT_EQ(chmod(directory.c_str(), 0755), 0);
    EXPECT_EQ(server.Stop(), StopResult::PathCleanupFailed);
    const auto error = server.LastError();
    EXPECT_NE(error.find("UDS cleanup refused"), std::string::npos);
    EXPECT_NE(error.find("mode 0700"), std::string::npos);
    EXPECT_NE(error.find(config.udsPath), std::string::npos);
    EXPECT_FALSE(GrpcServerTestPeer::HasThreadObject(server));
    EXPECT_FALSE(GrpcServerTestPeer::HasServer(server));
    EXPECT_FALSE(GrpcServerTestPeer::HasService(server));
    EXPECT_EQ(stats, 0);
    EXPECT_EQ(unlinks, 0);
    EXPECT_TRUE(GrpcServerTestPeer::HasIdentity(server));
    ASSERT_EQ(chmod(directory.c_str(), 0700), 0);
    EXPECT_EQ(server.Stop(), StopResult::Stopped);
    EXPECT_FALSE(GrpcServerTestPeer::HasIdentity(server));
    EXPECT_EQ(stats, 1);
    // 第三方可能已移除路径，因此允许 ENOENT 成功，不强制本层必须调用 unlink。
    EXPECT_LE(unlinks, 1);
    struct stat info {};
    ASSERT_EQ(lstat(config.udsPath.c_str(), &info), -1);
    EXPECT_EQ(errno, ENOENT);
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
// 逐个凭据失败都必须定位类别和路径；其他凭据使用真实有效夹具，避免前序失败遮蔽目标。
TEST_F(GrpcServerTest, TlsCredentialReadFailureNamesKindAndPathBeforeBuild)
{
    const char *kinds[] = {"private_key", "certificate", "ca"};
    const std::string certRoot = VIRTRUST_TEST_CERT_DIR;
    for (int kind = 0; kind < 3; ++kind) {
        for (bool empty : {false, true}) {
            SCOPED_TRACE(kind);
            SCOPED_TRACE(empty);
            config.skPath = certRoot + "/server/sk.pem";
            config.certPath = certRoot + "/server/cert.pem";
            config.caPath = certRoot + "/ca/cert.pem";
            ASSERT_FALSE(ReadFile(config.skPath).empty());
            ASSERT_FALSE(ReadFile(config.certPath).empty());
            ASSERT_FALSE(ReadFile(config.caPath).empty());
            const auto path = directory + "/" + kinds[kind] + (empty ? "-empty" : "-missing");
            if (empty) {
                ASSERT_TRUE(WriteFixture(path, ""));
                ASSERT_EQ(std::filesystem::file_size(path), 0u);
            } else {
                ASSERT_FALSE(std::filesystem::exists(path));
            }
            if (kind == 0) {
                config.skPath = path;
            } else if (kind == 1) {
                config.certPath = path;
            } else {
                config.caPath = path;
            }
            std::atomic<int> builds{0};
            GrpcServer server(config);
            GrpcServerTestPeer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
                ++builds;
                return builder.BuildAndStart();
            };
            EXPECT_EQ(server.Start(), LinkRc::ERROR);
            const auto detail = server.LastError();
            const auto expected = std::string("TLS ") + kinds[kind] + " read failed or file is empty [" + path +
                                  "]; no plaintext fallback";
            EXPECT_NE(detail.find(expected), std::string::npos);
            EXPECT_EQ(detail.find("BEGIN PRIVATE KEY"), std::string::npos);
            EXPECT_EQ(detail.find("BEGIN CERTIFICATE"), std::string::npos);
            EXPECT_EQ(builds.load(), 0);
            EXPECT_EQ(server.Stop(), StopResult::Stopped);
            EXPECT_FALSE(GrpcServerTestPeer::HasThreadObject(server));
            EXPECT_FALSE(GrpcServerTestPeer::HasServer(server));
            EXPECT_FALSE(GrpcServerTestPeer::HasService(server));
            EXPECT_FALSE(GrpcServerTestPeer::HasIdentity(server));
            EXPECT_FALSE(std::filesystem::exists(config.udsPath));
        }
    }
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

TEST_F(GrpcServerTest, ParentOpenFailureDiagnosticIncludesErrno)
{
    const std::string file = directory + "/not-directory";
    ASSERT_TRUE(WriteFixture(file, "keep"));
    config.udsPath = file + "/rpc.sock";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    EXPECT_NE(server.LastError().find(config.udsPath), std::string::npos);
    EXPECT_NE(server.LastError().find("UDS parent check failed"), std::string::npos);
    EXPECT_NE(server.LastError().find("errno=" + std::to_string(ENOTDIR)), std::string::npos);
}
// 不完整的 TLS 配置不能静默回退到明文监听。
TEST_F(GrpcServerTest, PartialTlsConfigurationIsRejected)
{
    for (unsigned mask = 1; mask < 7; ++mask) {
        SCOPED_TRACE(mask);
        std::atomic<int> builds{0};
        config.skPath = (mask & 1) ? directory + "/key" : "";
        config.certPath = (mask & 2) ? directory + "/cert" : "";
        config.caPath = (mask & 4) ? directory + "/ca" : "";
        GrpcServer server(config);
        GrpcServerTestPeer::Ops(server).build = [&](grpc::ServerBuilder &builder) {
            ++builds;
            return builder.BuildAndStart();
        };
        EXPECT_EQ(server.Start(), LinkRc::ERROR) << mask;
        EXPECT_NE(server.LastError().find("Incomplete TLS configuration"), std::string::npos);
        std::string missing;
        if (!(mask & 1)) {
            missing += "private_key ";
        }
        if (!(mask & 2)) {
            missing += "certificate ";
        }
        if (!(mask & 4)) {
            missing += "ca ";
        }
        const auto detail = server.LastError();
        const auto missingPosition = detail.find("missing=");
        EXPECT_NE(missingPosition, std::string::npos);
        if (missingPosition != std::string::npos) {
            EXPECT_EQ(detail.substr(missingPosition + std::string("missing=").size()), missing);
        }
        EXPECT_EQ(server.Stop(), StopResult::Stopped);
        EXPECT_EQ(builds.load(), 0);
        EXPECT_FALSE(GrpcServerTestPeer::HasThreadObject(server));
        EXPECT_FALSE(GrpcServerTestPeer::HasServer(server));
        EXPECT_FALSE(GrpcServerTestPeer::HasService(server));
    }
}

TEST_F(GrpcServerTest, MissingParentReportsListenersNotAttempted)
{
    config.udsPath = directory + "/missing/rpc.sock";
    GrpcServer server(config);
    ASSERT_EQ(server.Start(), LinkRc::ERROR);
    const auto error = server.LastError();
    EXPECT_NE(error.find("UDS parent check failed"), std::string::npos);
    EXPECT_NE(error.find("tcp=127.0.0.1:0"), std::string::npos);
    EXPECT_NE(error.find(config.udsPath), std::string::npos);
    EXPECT_NE(error.find("server_created=not_attempted"), std::string::npos);
    EXPECT_NE(error.find("tcp_result=not_attempted"), std::string::npos);
    EXPECT_NE(error.find("uds_result=not_attempted"), std::string::npos);
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
