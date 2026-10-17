/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "virtrust/api/admission_test_support.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust-sh/operator/op_utils.h"

// 复用真实命令分派代码，只为本测试改名入口函数。
#define main VirtrustShTestMain
#include "virtrust-sh/main.cpp"
#undef main

namespace {
std::vector<std::string> *attemptedUris = nullptr;
std::string failedUri;
int testConnection = 0;

virtrust::virConnectPtr OpenCreateTestConnection(const char *uri)
{
    attemptedUris->emplace_back(uri);
    return *attemptedUris->rbegin() == failedUri ? nullptr : &testConnection;
}

// 测试结束恢复 mock 函数，避免改变其他用例的连接行为。
class CreateConnectionProbe {
public:
    explicit CreateConnectionProbe(std::vector<std::string> &attempts)
        : original_(virtrust::Libvirt::GetInstance().virConnectOpen)
    {
        attemptedUris = &attempts;
        virtrust::Libvirt::GetInstance().virConnectOpen =
            virtrust::DlFun<virtrust::virConnectPtr, const char *>("virConnectOpen", OpenCreateTestConnection);
    }
    ~CreateConnectionProbe()
    {
        virtrust::Libvirt::GetInstance().virConnectOpen = original_;
        attemptedUris = nullptr;
        failedUri.clear();
    }
private:
    virtrust::DlFun<virtrust::virConnectPtr, const char *> original_;
};

int RunCreateCommand(std::vector<std::string> args)
{
    std::vector<char *> argv;
    for (auto &arg : args) { argv.push_back(arg.data()); }
    argv.push_back(nullptr);
    optind = 1;
    return ProcessArgs(static_cast<int>(args.size()), argv.data());
}

TEST(CliCreateConnectionTest, MainShortConnectionPrecedesCreateConnection)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    (void)RunCreateCommand({"virtrust-sh", "-c", "qemu:///main", "create", "--name", "VM",
                            "--connect", "qemu:///sub"});

    EXPECT_EQ(attempts, (std::vector<std::string>{"qemu:///main"}));
    EXPECT_EQ(state.admissionCalls, 1);
}

TEST(CliCreateConnectionTest, MainLongConnectionFallsBackToCreateConnection)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    failedUri = "qemu:///main";
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    (void)RunCreateCommand({"virtrust-sh", "--connect", "qemu:///main", "create", "--name", "VM",
                            "--connect=qemu:///sub"});

    EXPECT_EQ(attempts, (std::vector<std::string>{"qemu:///main", "qemu:///sub"}));
    EXPECT_EQ(state.admissionCalls, 1);
}

TEST(CliCreateConnectionTest, AllExplicitConnectionsFailWithoutDefaultFallback)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    failedUri = "qemu:///main";
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    EXPECT_EQ(RunCreateCommand({"virtrust-sh", "-c", "qemu:///main", "create", "--name", "VM"}), 1);

    EXPECT_EQ(attempts, (std::vector<std::string>{"qemu:///main"}));
    EXPECT_EQ(state.admissionCalls, 0);
}

TEST(CliCreateConnectionTest, MainCandidatesKeepAppearanceOrderBeforeSubcommand)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    failedUri = "qemu:///first";
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    (void)RunCreateCommand({"virtrust-sh", "-c", "qemu:///first", "--connect=qemu:///second", "create",
                            "--name", "VM", "-cqemu:///third"});

    EXPECT_EQ(attempts, (std::vector<std::string>{"qemu:///first", "qemu:///second"}));
    EXPECT_EQ(state.admissionCalls, 1);
}

TEST(CliCreateConnectionTest, InvalidCandidateIsSkippedBeforeTryingNextValidOne)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    (void)RunCreateCommand({"virtrust-sh", "--connect=", "create", "--name", "VM",
                            "--connect=qemu:///valid"});

    EXPECT_EQ(attempts, (std::vector<std::string>{"qemu:///valid"}));
    EXPECT_EQ(state.admissionCalls, 1);
}

TEST(CliCreateConnectionTest, NoExplicitCandidateUsesProjectDefaultOnce)
{
    std::vector<std::string> attempts;
    CreateConnectionProbe probe(attempts);
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = 0;

    (void)RunCreateCommand({"virtrust-sh", "create", "--name", "VM"});

    EXPECT_EQ(attempts, (std::vector<std::string>{std::string(virtrust::VIRTRUST_DEFAULT_URI)}));
    EXPECT_EQ(state.admissionCalls, 1);
}

TEST(CliBusyTest, MapsApiBusyWithoutUnknownFallback)
{
    EXPECT_EQ(static_cast<unsigned>(virtrust::ParseVirtrustRc(virtrust::VirtrustRc::BUSY)), 3U);
}

TEST(CliBusyTest, ShowsBusyAndExitsFailure)
{
    auto &state = virtrust::test::AdmissionState();
    state.admissionCalls = state.legacyOpens = state.businessCalls = 0;
    virtrust::NodeAdmission migration;
    ASSERT_EQ(migration.TryAcquire(virtrust::AdmissionKind::Migration, state.directory, geteuid()),
              virtrust::LockOutcome::Acquired);
    char command[] = "virtrust-sh";
    char action[] = "start";
    char flag[] = "--only-tsb";
    char uuid[] = "12345678-1234-1234-1234-123456789002";
    char *argv[] = {command, action, flag, uuid, nullptr};
    optind = 1;
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    const int status = ProcessOp(4, argv, {});
    const std::string stderrText = testing::internal::GetCapturedStderr();
    const std::string stdoutText = testing::internal::GetCapturedStdout();
    EXPECT_EQ(status, 1);
    EXPECT_NE(stderrText.find("Node is busy"), std::string::npos);
    EXPECT_EQ(stderrText.find("Unknown virtrust return code"), std::string::npos);
    // BUSY 已由 stderr 单独说明，不应再向 stdout 报告成功或通用失败。
    EXPECT_TRUE(stdoutText.empty()) << stdoutText;
    EXPECT_EQ(state.admissionCalls, 1);
    EXPECT_EQ(state.legacyOpens, 0);
    EXPECT_EQ(state.businessCalls, 0);
}
} // 匿名命名空间
