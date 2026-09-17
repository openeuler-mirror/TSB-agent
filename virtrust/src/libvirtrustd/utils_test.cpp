/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <cstdio>
#include <fstream>
#include <string>

#include "gtest/gtest.h"

#include "libvirtrustd/defines.h"
#include "libvirtrustd/utils.h"

namespace virtrust::test {
namespace {

constexpr char TEST_CONFIG_PREFIX[] = "/tmp/virtrustd_ut_";

std::string WriteTempConfig(const std::string &fileName, const std::string &content)
{
    const std::string path = std::string(TEST_CONFIG_PREFIX) + fileName;
    std::ofstream out(path);
    out << content;
    return path;
}

} // namespace

// Full config file: every key is parsed into the LinkConfig fields
TEST(UtilsTest, ParseFullConfig)
{
    const std::string path = WriteTempConfig("full.json", R"({
        "caPath": "/etc/virtrust/ca.pem",
        "certPath": "/etc/virtrust/server-cert.pem",
        "skPath": "/etc/virtrust/server-sk.pem",
        "ip": "192.168.10.10",
        "udsPath": "/var/run/virtrustd.sock",
        "port": 8888
    })");

    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->caPath, "/etc/virtrust/ca.pem");
    EXPECT_EQ(config->certPath, "/etc/virtrust/server-cert.pem");
    EXPECT_EQ(config->skPath, "/etc/virtrust/server-sk.pem");
    EXPECT_EQ(config->ip, "192.168.10.10");
    EXPECT_EQ(config->udsPath, "/var/run/virtrustd.sock");
    EXPECT_EQ(config->port, 8888);

    std::remove(path.c_str());
}

// Empty json object: all keys fall back to the defaults in defines.h
TEST(UtilsTest, MissingKeysUseDefaultValues)
{
    const std::string path = WriteTempConfig("empty.json", "{}");

    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    // NOTE caPath falls back to LIBVIRTRUSTD_SERVER_ADDR per the current
    // FIND_KEY(caPath, ...) in utils.cpp; may be intended to be
    // LIBVIRTRUSTD_CA_PATH instead.
    EXPECT_EQ(config->caPath, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    EXPECT_EQ(config->certPath, std::string(LIBVIRTRUSTD_CERT_PATH));
    EXPECT_EQ(config->skPath, std::string(LIBVIRTRUSTD_SK_PATH));
    EXPECT_EQ(config->ip, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    EXPECT_EQ(config->udsPath, std::string(LIBVIRTRUSTD_UDS_PATH));
    EXPECT_EQ(config->port, LIBVIRTRUSTD_SERVER_PORT);

    std::remove(path.c_str());
}

// Wrong value type for a key: the key is skipped and its default is kept
TEST(UtilsTest, WrongTypeFallsBackToDefault)
{
    const std::string path = WriteTempConfig("wrong_type.json", R"({
        "port": "not-a-number"
    })");

    auto config = MakeLinkConfigFromJsonFile(path);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->port, LIBVIRTRUSTD_SERVER_PORT);

    std::remove(path.c_str());
}

// Malformed json content: parse error leads to nullopt
TEST(UtilsTest, InvalidJsonReturnsNullopt)
{
    const std::string path = WriteTempConfig("invalid.json", "{ not valid json !!!");

    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());

    std::remove(path.c_str());
}

// Nonexistent file: realpath fails and leads to nullopt
TEST(UtilsTest, NonexistentPathReturnsNullopt)
{
    const std::string path = std::string(TEST_CONFIG_PREFIX) + "no_such_file.json";
    std::remove(path.c_str()); // make sure the file does not exist

    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());
}

// File larger than MAX_FILE_SIZE (10MB) is rejected by CheckFileStat
TEST(UtilsTest, OversizedFileReturnsNullopt)
{
    const std::string path = WriteTempConfig("oversized.json", "");
    {
        std::ofstream out(path);
        const std::string chunk(1024 * 1024, ' '); // 1MB
        for (size_t i = 0; i < 11; ++i) {
            out << chunk;
        }
    }

    auto config = MakeLinkConfigFromJsonFile(path);
    EXPECT_FALSE(config.has_value());

    std::remove(path.c_str());
}

} // namespace virtrust::test
