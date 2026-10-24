/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace virtrust {

// 请求和回复可能包含证书、密钥及密文，只留在有界进程内存中，不写入持久化介质。
// 仅覆盖当前守护进程存活期间的有限回放窗口；不提供跨进程或无限期幂等性。
class MigrationReplayCache {
public:
    // 使用单调时钟计算缓存存活时间，不受系统时间调整影响。
    using Clock = std::chrono::steady_clock;

    // 同一迁移尝试的五条节点间消息分别去重，不能跨阶段复用回复。
    enum class Step : uint8_t { Prepare, Exchange, Start, Transfer, Finish };
    // Begin 的准入结论：只有 Execute 允许进入有副作用的业务代码。
    enum class Decision : uint8_t { Execute, Replay, InProgress, Conflict, Capacity, Unavailable };
    // 最终结果查询只观察 Finish 阶段；Unknown 不代表该阶段未执行。
    enum class FinalState : uint8_t { Unknown, InProgress, CompletedSuccess, CompletedFailure };

    // 查询快照中的回复仅供失败诊断解析，不用它重新执行迁移。
    struct FinalSnapshot {
        // 查询只能依据显式记录得出完成结论；默认状态始终为未知。
        FinalState state = FinalState::Unknown;
        // 仅完成且可回放时保存原始序列化回复，用于读取失败诊断。
        std::string reply;
    };

    // Begin 发给 Complete 的登记凭据；generation 防止迟到回调完成错误条目。
    struct Admission {
        Decision decision = Decision::Unavailable;
        std::string reply;
        std::string attemptId;
        Step step = Step::Prepare;
        uint64_t generation = 0;
    };

    // activeProbe 按 attempt ID 查询当前会话是否仍活跃；活跃时完成记录超过 TTL 也不淘汰。
    // 未提供探针时，仅按 TTL 淘汰已完成记录；缓存本身不管理会话生命周期。
    explicit MigrationReplayCache(size_t maxEntries = 256, size_t maxBytes = 16 * 1024 * 1024,
                                  std::chrono::seconds ttl = std::chrono::minutes(10),
                                  std::function<bool(const std::string &)> activeProbe = {});

    // 先登记执行中条目，再允许调用方运行阶段业务；重复请求按决策返回，不在这里执行副作用。
    Admission Begin(const std::string &attemptId, Step step, const std::string &request,
                    Clock::time_point now = Clock::now(), const std::string &uuid = {});

    // 返回 false 表示结果无法保留；仍留下墓碑，后续重复请求必须拒绝而非再次执行。
    bool Complete(const Admission &admission, const std::string &reply,
                  Clock::time_point now = Clock::now(),
                  std::optional<bool> finalBusinessSuccess = std::nullopt) noexcept;

    // 业务或回复序列化失败时留下不可回放墓碑，避免重复请求重新执行。
    void CompleteUnreplayable(const Admission &admission, Clock::time_point now = Clock::now()) noexcept;

    // 仅返回本进程记录的最终阶段处理结果；缺失记录不能解释为请求未执行。
    FinalSnapshot QueryFinal(const std::string &uuid, const std::string &attemptId,
                             Clock::time_point now = Clock::now());

private:
    // 缓存键只由一次迁移尝试和阶段组成；完整请求另存于 Entry 供冲突检查。
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
    // 一个阶段的请求、回复与执行状态；uuid 用于最终结果查询时核对身份。
    struct Entry {
        // 查询时再次核对 UUID，避免只持有 attempt ID 的调用方读取错误对象。
        std::string uuid;
        // 以完整请求字节检查同键重试是否更换负载。
        std::string request;
        // 完成后才写入；保存失败时条目仍保留为不可回放墓碑。
        std::string reply;
        Clock::time_point completedAt{};
        uint64_t generation = 0;
        bool inProgress = true;
        bool hasReply = false;
        // 仅 Finish 阶段有值；未得出可信结论时查询返回 Unknown。
        std::optional<bool> finalBusinessSuccess;
    };

    // 惰性清理：仅在 Begin/QueryFinal 时扫描，不启动后台清理线程。
    void ExpireCompleted(Clock::time_point now);

    // 条目数与计数字节双重上限；字节数不包括容器和对象本身的内存开销。
    const size_t maxEntries_;
    const size_t maxBytes_;
    // TTL 从阶段完成时间开始计算；执行中条目不按 TTL 删除。
    const std::chrono::seconds ttl_;
    // 外部注入的活跃会话探针；仅参与过期判断，不参与准入或最终结果判定。
    const std::function<bool(const std::string &)> activeProbe_;
    // 保护条目、计数字节和代数，使并发相同请求只出现一个 Execute。
    std::mutex mutex_;
    std::unordered_map<Key, Entry, KeyHash> entries_;
    // 计数字节包括 attempt ID、UUID、请求、回复，不包括容器管理开销。
    size_t bytes_ = 0;
    // 每次新登记递增，Complete 只接受对应代数的凭据。
    uint64_t nextGeneration_ = 0;
};

} // namespace virtrust
