/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <optional>

#include "libvirtrustd/defines.h"
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"

#include "virtrust/link/link_config_builder.h"

namespace virtrust {

namespace {

constexpr uint32_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10* 1024 * 1024

std::optional<std::string> CanonicalPath(const std::string &path)
{
    if (path.empty() || path.size() > 4096L) {
        return std::nullopt;
    }

    /* It will callocate memory to store path*/
    std::array<char, PATH_MAX> resolvedPath;
    if (realpath(path.c_str(), resolvedPath.data()) == nullptr) {
        return std::nullopt;
    }
    return resolvedPath.data();
}

bool IsAbsolutePath(const std::string &filePath)
{
    if (filePath.length() == 0) {
        return false;
    }
    if (filePath[0] != '/') {
        return false;
    }
    if (strstr(filePath.c_str(), "/../") != nullptr || strstr(filePath.c_str(), "/./") != nullptr) {
        return false;
    }
    return true;
}

bool CheckFileAccess(const std::string &path, int mode)
{
    return access(path.c_str(), mode) != -1;
}

bool CheckFileStat(const std::string &filePath)
{
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        return false;
    }

    if ((st.st_mode & S_IFMT) != S_IFREG || (st.st_size > MAX_FILE_SIZE)) {
        return false;
    }
    return true;
}

bool CheckConfigFile(const std::string &path)
{
    if (!IsAbsolutePath(path)) {
        VIRTRUST_LOG_ERROR("Got relatinve path.");
        return false;
    }
    if (!CheckFileStat(path)) {
        VIRTRUST_LOG_ERROR("Check path stat failed.");
        return false;
    }
    if (!CheckFileAccess(path, F_OK | R_OK)) {
        VIRTRUST_LOG_ERROR("File path access is not valid.");
        return false;
    }
    return true;
}

std::optional<rapidjson::Document> ReadJsonFile(const std::string &path)
{
    // canonical path
    auto realPath = CanonicalPath(path);
    if (!realPath) {
        VIRTRUST_LOG_ERROR("Canonical path failed.");
        return std::nullopt;
    }
    // check the validity of path
    if (!CheckConfigFile(realPath.value())) {
        VIRTRUST_LOG_ERROR("Read config error. File access check failed: {}", realPath.value());
        return std::nullopt;
    }

    // read path into ifstream
    std::ifstream file(realPath.value());
    if (!file.is_open()) {
        VIRTRUST_LOG_ERROR("Read config error. Cannot open file: {}", realPath.value());
        return std::nullopt;
    }

    // handle ifstream to rapidjson
    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);

    // in case of parse error
    if (doc.HasParseError()) {
        VIRTRUST_LOG_ERROR("Read config error. Cannto parse file into json: {}", realPath.value());
        return std::nullopt;
    }

    return doc;
}

template <typename T>
std::optional<T> FindJsonKey(const rapidjson::Document &jsonDoc, const std::string &key, T defaultValue)
{
    if (!jsonDoc.HasMember(key.data())) {
        VIRTRUST_LOG_WARN("ParseJsonDocToConfig: Failed to find config key:{}, Set it to default value.", key);
        return std::optional<T>(defaultValue);
    }

    const auto &value = jsonDoc[key.data()];
    if constexpr (std::is_same_v<T, std::string>) {
        return value.IsString() ? std::optional<T>(std::string(value.GetString())) : std::nullopt;
    } else if constexpr (std::is_same_v<T, uint16_t>) {
        return value.IsUint() ? std::optional<T>(value.GetUint()) : std::nullopt;
    } else {
        return std::nullopt;
    }
}

LinkConfig ParseJsonDocToConfig(const rapidjson::Document &jsonDoc)
{
    auto configBuidler = LinkConfigBuilder();

#define FIND_KEY(NAME, T, DEFAULT_VALUE)                          \
    do {                                                          \
        auto tmp = FindJsonKey<T>(jsonDoc, #NAME, DEFAULT_VALUE); \
        configBuidler.NAME(tmp.value_or(DEFAULT_VALUE));          \
    } while (0)

    FIND_KEY(caPath, std::string, std::string(LIBVIRTRUSTD_CA_PATH));
    FIND_KEY(certPath, std::string, std::string(LIBVIRTRUSTD_CERT_PATH));
    FIND_KEY(skPath, std::string, std::string(LIBVIRTRUSTD_SK_PATH));
    FIND_KEY(ip, std::string, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    FIND_KEY(udsPath, std::string, std::string(LIBVIRTRUSTD_UDS_PATH));
    FIND_KEY(port, uint16_t, LIBVIRTRUSTD_SERVER_PORT);
    FIND_KEY(sourceCleanupMaxAttempts, uint16_t, DEFAULT_SOURCE_CLEANUP_MAX_ATTEMPTS);
    // 字段缺省时使用 LinkConfig 中同一组默认值；显式错误值已由外层入口拒绝。
    FIND_KEY(rpcRetryMaxAttempts, uint16_t, DEFAULT_RPC_RETRY_MAX_ATTEMPTS);
    FIND_KEY(rpcRetryInitialBackoffMs, uint16_t, DEFAULT_RPC_RETRY_INITIAL_BACKOFF_MS);
    FIND_KEY(rpcRetryMaxBackoffMs, uint16_t, DEFAULT_RPC_RETRY_MAX_BACKOFF_MS);

#undef FIND_KEY
    return configBuidler.Build();
}

} // namespace

std::optional<LinkConfig> MakeLinkConfigFromJsonFile(const std::string &configPath)
{
    auto jsonDoc = ReadJsonFile(configPath);
    if (!jsonDoc.has_value() || !jsonDoc->IsObject()) {
        return std::nullopt;
    }
    // 缺省使用固定生产端点；显式配置必须完全一致，避免客户端与服务端连接不同路径。
    // 按 JSON 字符串实际长度比较，不能把嵌入空字符后的内容截断后误判为合法。
    if (jsonDoc->HasMember("udsPath")) {
        const auto &path = (*jsonDoc)["udsPath"];
        if (!path.IsString() || std::string_view(path.GetString(), path.GetStringLength()) != LIBVIRTRUSTD_UDS_PATH) {
            VIRTRUST_LOG_ERROR("Invalid udsPath: expected the fixed endpoint {}", LIBVIRTRUSTD_UDS_PATH);
            return std::nullopt;
        }
    }
    // 显式清理次数必须有界；不能把错误类型静默替换成缺省值。
    if (jsonDoc->HasMember("sourceCleanupMaxAttempts")) {
        const auto &attempts = (*jsonDoc)["sourceCleanupMaxAttempts"];
        if (!attempts.IsUint() || attempts.GetUint() < 1 ||
            attempts.GetUint() > MAX_SOURCE_CLEANUP_MAX_ATTEMPTS) {
            VIRTRUST_LOG_ERROR("Invalid sourceCleanupMaxAttempts: expected an integer from 1 to {}",
                               MAX_SOURCE_CLEANUP_MAX_ATTEMPTS);
            return std::nullopt;
        }
    }
    // 三个参数分别验证类型和上限，再验证退避窗口关系，避免非法值被静默替换。
    const auto validBounded = [&](const char *name, uint32_t maximum) {
        if (!jsonDoc->HasMember(name)) {
            return true;
        }
        const auto &value = (*jsonDoc)[name];
        if (!value.IsUint() || value.GetUint() < 1 || value.GetUint() > maximum) {
            VIRTRUST_LOG_ERROR("Invalid {}: expected an integer from 1 to {}", name, maximum);
            return false;
        }
        return true;
    };
    if (!validBounded("rpcRetryMaxAttempts", MAX_RPC_RETRY_MAX_ATTEMPTS) ||
        !validBounded("rpcRetryInitialBackoffMs", MAX_RPC_RETRY_INITIAL_BACKOFF_MS) ||
        !validBounded("rpcRetryMaxBackoffMs", MAX_RPC_RETRY_MAX_BACKOFF_MS)) {
        return std::nullopt;
    }
    // 单字段省略时也要与另一个字段比较，避免“显式最大值 < 缺省初值”的组合。
    const auto initial = jsonDoc->HasMember("rpcRetryInitialBackoffMs") ?
        (*jsonDoc)["rpcRetryInitialBackoffMs"].GetUint() : DEFAULT_RPC_RETRY_INITIAL_BACKOFF_MS;
    const auto maximum = jsonDoc->HasMember("rpcRetryMaxBackoffMs") ?
        (*jsonDoc)["rpcRetryMaxBackoffMs"].GetUint() : DEFAULT_RPC_RETRY_MAX_BACKOFF_MS;
    if (maximum < initial) {
        VIRTRUST_LOG_ERROR("Invalid RPC retry backoff: maximum must be at least the initial delay");
        return std::nullopt;
    }
    return ParseJsonDocToConfig(jsonDoc.value());
}
} // namespace virtrust
