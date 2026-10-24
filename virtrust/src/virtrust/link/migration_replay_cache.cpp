/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust/link/migration_replay_cache.h"

#include <functional>
#include <utility>

namespace virtrust {

MigrationReplayCache::MigrationReplayCache(size_t maxEntries, size_t maxBytes, std::chrono::seconds ttl,
                                           std::function<bool(const std::string &)> activeProbe)
    : maxEntries_(maxEntries), maxBytes_(maxBytes), ttl_(ttl), activeProbe_(std::move(activeProbe))
{}

size_t MigrationReplayCache::KeyHash::operator()(const Key &key) const noexcept
{
    return std::hash<std::string>{}(key.attemptId) ^ (static_cast<size_t>(key.step) << 1);
}

void MigrationReplayCache::ExpireCompleted(Clock::time_point now)
{
    for (auto it = entries_.begin(); it != entries_.end();) {
        // 会话仍在运行时旧阶段可能晚于 TTL 被重发；此时不能把它当成全新动作。
        if (it->second.inProgress || now - it->second.completedAt < ttl_ ||
            (activeProbe_ && activeProbe_(it->first.attemptId))) {
            ++it;
            continue;
        }
        bytes_ -= it->first.attemptId.size() + it->second.request.size() + it->second.reply.size();
        it = entries_.erase(it);
    }
}

MigrationReplayCache::Admission MigrationReplayCache::Begin(const std::string &attemptId, Step step,
                                                            const std::string &request, Clock::time_point now)
{
    std::lock_guard<std::mutex> guard(mutex_);
    ExpireCompleted(now);
    Admission result;
    result.attemptId = attemptId;
    result.step = step;
    const Key key{attemptId, step};
    const auto it = entries_.find(key);
    if (it != entries_.end()) {
        // 同键先比请求内容：不同负载即使前一次仍在执行，也不能被当成同一重试。
        if (it->second.request != request) {
            result.decision = Decision::Conflict;
        } else if (it->second.inProgress) {
            result.decision = Decision::InProgress;
        } else if (!it->second.hasReply) {
            result.decision = Decision::Unavailable;
        } else {
            result.decision = Decision::Replay;
            result.reply = it->second.reply;
        }
        return result;
    }
    const size_t needed = attemptId.size() + request.size();
    // 容量不足时拒绝新请求，不驱逐执行中条目给第二次副作用腾空间。
    if (entries_.size() >= maxEntries_ || needed > maxBytes_ || bytes_ > maxBytes_ - needed) {
        result.decision = Decision::Capacity;
        return result;
    }
    result.generation = ++nextGeneration_;
    // 先登记为执行中再放开互斥锁，使并发到达的相同阶段只能看到 InProgress。
    entries_.emplace(key, Entry{request, {}, {}, result.generation, true, false});
    bytes_ += needed;
    result.decision = Decision::Execute;
    return result;
}

bool MigrationReplayCache::Complete(const Admission &admission, const std::string &reply,
                                    Clock::time_point now) noexcept
{
    try {
        std::lock_guard<std::mutex> guard(mutex_);
        const auto it = entries_.find(Key{admission.attemptId, admission.step});
        if (it == entries_.end() || !it->second.inProgress || it->second.generation != admission.generation) {
            return false;
        }
        // 代数防止迟到的完成回调把同键的新一轮记录改写掉。
        // 保留墓碑可阻止缓存空间不足时相同阶段再次执行不可逆业务。
        it->second.inProgress = false;
        it->second.completedAt = now;
        if (bytes_ > maxBytes_ || reply.size() > maxBytes_ - bytes_) {
            return false;
        }
        it->second.reply = reply;
        it->second.hasReply = true;
        bytes_ += reply.size();
        return true;
    } catch (...) {
        return false;
    }
}

void MigrationReplayCache::CompleteUnreplayable(const Admission &admission, Clock::time_point now) noexcept
{
    try {
        std::lock_guard<std::mutex> guard(mutex_);
        const auto it = entries_.find(Key{admission.attemptId, admission.step});
        if (it != entries_.end() && it->second.generation == admission.generation) {
            it->second.inProgress = false;
            it->second.completedAt = now;
        }
    } catch (...) {
    }
}

} // namespace virtrust
