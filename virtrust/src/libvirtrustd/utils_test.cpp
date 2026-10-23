/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

#include "gtest/gtest.h"
#include "libvirtrustd/defines.h"
#include "libvirtrustd/utils.h"

#include "virtrust/api/defines.h"

namespace virtrust::test {
namespace {

// 每个对象独占随机临时目录；断言提前返回时也由析构清理，不接触固定公共文件名。
class ConfigDirectory {
public:
    ConfigDirectory() : created_(mkdtemp(directory_) != nullptr)
    {}
    ~ConfigDirectory()
    {
        if (created_) {
            std::error_code error;
            std::filesystem::remove_all(directory_, error);
            EXPECT_FALSE(error) << "Failed to remove config fixture directory: " << error.message();
        }
    }
    ConfigDirectory(const ConfigDirectory &) = delete;
    ConfigDirectory &operator=(const ConfigDirectory &) = delete;

    bool IsValid() const noexcept
    {
        return created_;
    }
    std::string Path(const std::string &name = "") const
    {
        return created_ ? std::string(directory_) + "/" + name : std::string{};
    }
    // 空返回表示准备失败；调用方必须先断言非空，才能把解析失败归因于配置内容。
    std::string Write(const std::string &name, const std::string &content) const
    {
        if (!created_) {
            return {};
        }
        const auto path = Path(name);
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) {
            return {};
        }
        out << content;
        out.close();
        if (!out.good()) {
            return {};
        }
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        return !error && size == content.size() ? path : std::string{};
    }

private:
    char directory_[sizeof("/tmp/virtrust-config-ut.XXXXXX")] = "/tmp/virtrust-config-ut.XXXXXX";
    bool created_;
};
// 统一检查临时目录创建结果；文件和目录由成员对象自动清理。
class UtilsTest : public testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_TRUE(directory_.IsValid()) << "Failed to create config fixture directory";
    }
    std::string WriteTempConfig(const std::string &name, const std::string &content)
    {
        return directory_.Write(name, content);
    }
    ConfigDirectory directory_;
};
} // 匿名命名空间

// 同名文件位于不同私有目录；局部作用域返回后会自动删除夹具。
TEST(ConfigDirectoryTest, IsolatesNamesAndCleansUpOnReturn)
{
    std::string firstPath;
    std::string secondPath;
    const auto prepareAndReturn = [&] {
        ConfigDirectory first;
        ConfigDirectory second;
        ASSERT_TRUE(first.IsValid());
        ASSERT_TRUE(second.IsValid());
        firstPath = first.Path();
        secondPath = second.Path();
        ASSERT_NE(firstPath, secondPath);
        ASSERT_FALSE(first.Write("config.json", "{}").empty());
        ASSERT_FALSE(second.Write("config.json", "[]").empty());
        EXPECT_TRUE(std::filesystem::exists(firstPath + "config.json"));
        EXPECT_TRUE(std::filesystem::exists(secondPath + "config.json"));
        return;
    };
    prepareAndReturn();
    ASSERT_FALSE(firstPath.empty());
    ASSERT_FALSE(secondPath.empty());
    EXPECT_FALSE(std::filesystem::exists(firstPath));
    EXPECT_FALSE(std::filesystem::exists(secondPath));
}

// 写入前置条件失败必须可被调用方识别，不能返回看似有效的配置路径。
TEST_F(UtilsTest, FailedFixtureWriteDoesNotReturnAPath)
{
    ASSERT_FALSE(std::filesystem::exists(directory_.Path("missing-parent")));
    EXPECT_TRUE(WriteTempConfig("missing-parent/config.json", "{}").empty());
}

// 显式完整配置应逐项解析为对应字段。
TEST_F(UtilsTest, ParseFullConfig)
{
    const std::string path = WriteTempConfig("full.json", R"({
        "caPath": "/etc/virtrust/ca.pem",
        "certPath": "/etc/virtrust/server-cert.pem",
        "skPath": "/etc/virtrust/server-sk.pem",
        "ip": "192.168.10.10",
        "udsPath": "/run/virtrust/rpc.sock",
        "port": 8888,
        "sourceCleanupMaxAttempts": 2
    })");

    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->caPath, "/etc/virtrust/ca.pem");
    EXPECT_EQ(config->certPath, "/etc/virtrust/server-cert.pem");
    EXPECT_EQ(config->skPath, "/etc/virtrust/server-sk.pem");
    EXPECT_EQ(config->ip, "192.168.10.10");
    EXPECT_EQ(config->udsPath, "/run/virtrust/rpc.sock");
    EXPECT_EQ(config->port, 8888);
    EXPECT_EQ(config->sourceCleanupMaxAttempts, 2);
}

// 空 JSON 对象中缺失的配置项使用 defines.h 中各自的默认值。
TEST_F(UtilsTest, MissingKeysUseDefaultValues)
{
    const std::string path = WriteTempConfig("empty.json", "{}");

    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    // CA 默认值必须是证书路径，不能误用服务器监听地址。
    EXPECT_EQ(config->caPath, std::string(LIBVIRTRUSTD_CA_PATH));
    EXPECT_EQ(config->certPath, std::string(LIBVIRTRUSTD_CERT_PATH));
    EXPECT_EQ(config->skPath, std::string(LIBVIRTRUSTD_SK_PATH));
    EXPECT_EQ(config->caPath, "/etc/virtrust/certs/ca-cert.pem");
    EXPECT_EQ(config->certPath, "/etc/virtrust/certs/server-cert.pem");
    EXPECT_EQ(config->skPath, "/etc/virtrust/certs/server-key.pem");
    EXPECT_EQ(config->ip, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    EXPECT_EQ(config->udsPath, std::string(LIBVIRTRUSTD_UDS_PATH));
    EXPECT_EQ(config->udsPath, "/run/virtrust/rpc.sock");
    EXPECT_EQ(UDS_PATH, LIBVIRTRUSTD_UDS_PATH);
    EXPECT_EQ(config->port, LIBVIRTRUSTD_SERVER_PORT);
    EXPECT_EQ(config->sourceCleanupMaxAttempts, 3);
}

// 清理次数明确配置时只接受整数 1–10，避免零次清理或超量重复调用。
TEST_F(UtilsTest, RejectsInvalidSourceCleanupAttempts)
{
    for (const char *content : {R"({"sourceCleanupMaxAttempts":0})", R"({"sourceCleanupMaxAttempts":11})",
                                R"({"sourceCleanupMaxAttempts":-1})", R"({"sourceCleanupMaxAttempts":1.5})",
                                R"({"sourceCleanupMaxAttempts":"3"})", R"({"sourceCleanupMaxAttempts":null})"}) {
        SCOPED_TRACE(content);
        const auto path = WriteTempConfig("invalid_cleanup_attempts.json", content);
        ASSERT_FALSE(path.empty());
        EXPECT_FALSE(MakeLinkConfigFromJsonFile(path).has_value());
    }
}

TEST_F(UtilsTest, AcceptsSourceCleanupAttemptBounds)
{
    for (const auto &[content, expected] :
         {std::pair{R"({"sourceCleanupMaxAttempts":1})", 1},
          std::pair{R"({"sourceCleanupMaxAttempts":10})", 10}}) {
        SCOPED_TRACE(content);
        const auto path = WriteTempConfig("valid_cleanup_attempts.json", content);
        ASSERT_FALSE(path.empty());
        const auto config = MakeLinkConfigFromJsonFile(path);
        ASSERT_TRUE(config.has_value());
        EXPECT_EQ(config->sourceCleanupMaxAttempts, expected);
    }
}

// UDS 配置只接受固定生产路径，错误类型和嵌入空字符不得退回默认值或截断后接受。
TEST_F(UtilsTest, RejectsUnsupportedUdsConfiguration)
{
    for (const char *content :
         {R"({"udsPath":"/tmp/grpc.sock"})", R"({"udsPath":"/var/run/virtrustd.sock"})", R"({"udsPath":""})",
          R"({"udsPath":null})", R"({"udsPath":42})", R"({"udsPath":"/run/virtrust/rpc.sock\u0000suffix"})"}) {
        SCOPED_TRACE(content);
        const auto path = WriteTempConfig("unsupported_uds.json", content);
        ASSERT_FALSE(path.empty());
        EXPECT_FALSE(MakeLinkConfigFromJsonFile(path).has_value());
    }
}

// 非对象 JSON 不具备配置字段，必须拒绝，避免进入 HasMember 的对象前置条件。
TEST_F(UtilsTest, RejectsNonObjectConfiguration)
{
    for (const char *content : {"null", "[]", "42", "true", "\"text\""}) {
        SCOPED_TRACE(content);
        const auto path = WriteTempConfig("non_object.json", content);
        ASSERT_FALSE(path.empty());
        EXPECT_FALSE(MakeLinkConfigFromJsonFile(path).has_value());
    }
}

// 非 UDS 字段继续保持原有的错误类型回退策略。
TEST_F(UtilsTest, WrongTypeFallsBackToDefault)
{
    const std::string path = WriteTempConfig("wrong_type.json", R"({
        "port": "not-a-number"
    })");

    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->port, LIBVIRTRUSTD_SERVER_PORT);
}

// JSON 语法错误应返回空配置。
TEST_F(UtilsTest, InvalidJsonReturnsNullopt)
{
    const std::string path = WriteTempConfig("invalid.json", "{ not valid json !!!");

    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());
}

// 在私有目录中使用未创建的文件，验证路径解析失败。
TEST_F(UtilsTest, NonexistentPathReturnsNullopt)
{
    const std::string path = directory_.Path("no_such_file.json");
    ASSERT_FALSE(std::filesystem::exists(path));

    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());
}

// 确认超限文件实际写入，再验证超过 10 MiB 的配置被拒绝。
TEST_F(UtilsTest, OversizedFileReturnsNullopt)
{
    const auto path = WriteTempConfig("oversized.json", std::string(11 * 1024 * 1024, ' '));
    ASSERT_FALSE(path.empty());
    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());
}

} // 命名空间 virtrust::test
