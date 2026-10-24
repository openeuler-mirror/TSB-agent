/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace virtrust {

// 请求和回复可能包含证书、密钥及密文，只留在有界进程内存中，不写入持久化介质。
// 仅覆盖当前守护进程存活期间的有限回放窗口；不提供跨进程或无限期幂等性。
class MigrationReplayCache {
public:
    using Clock = std::chrono::steady_clock;

    enum class Step : uint8_t { Prepare, Exchange, Start, Transfer, Finish };
    enum class Decision : uint8_t { Execute, Replay, InProgress, Conflict, Capacity, Unavailable };

    struct Admission {
        Decision decision = Decision::Unavailable;
        std::string reply;
        std::string attemptId;
        Step step = Step::Prepare;
        uint64_t generation = 0;
    };

    explicit MigrationReplayCache(size_t maxEntries = 256, size_t maxBytes = 16 * 1024 * 1024,
                                  std::chrono::seconds ttl = std::chrono::minutes(10),
                                  std::function<bool(const std::string &)> activeProbe = {});

    Admission Begin(const std::string &attemptId, Step step, const std::string &request,
                    Clock::time_point now = Clock::now());

    // 返回 false 表示结果无法保留；仍留下墓碑，后续重复请求必须拒绝而非再次执行。
    bool Complete(const Admission &admission, const std::string &reply,
                  Clock::time_point now = Clock::now()) noexcept;

    void CompleteUnreplayable(const Admission &admission, Clock::time_point now = Clock::now()) noexcept;

private:
    struct Key {
        std::string attemptId;
        Step step;
        bool operator==(const Key &other) const noexcept
        {
            return step == other.step && attemptId == other.attemptId;
        }
    };
    struct KeyHash {
        size_t operator()(const Key &key) const noexcept;
    };
    struct Entry {
        std::string request;
        std::string reply;
        Clock::time_point completedAt{};
        uint64_t generation = 0;
        bool inProgress = true;
        bool hasReply = false;
    };

    void ExpireCompleted(Clock::time_point now);

    const size_t maxEntries_;
    const size_t maxBytes_;
    const std::chrono::seconds ttl_;
    const std::function<bool(const std::string &)> activeProbe_;
    std::mutex mutex_;
    std::unordered_map<Key, Entry, KeyHash> entries_;
    size_t bytes_ = 0;
    uint64_t nextGeneration_ = 0;
};

} // namespace virtrust
