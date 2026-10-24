/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "virtrust/link/migration_replay_cache.h"
#include "virtrust/link/migration_attempt_id.h"

namespace virtrust {
namespace {

TEST(MigrationAttemptIdTest, GeneratesDistinctFixedLengthHexIdentifiers)
{
    const auto first = GenerateMigrationAttemptId();
    const auto second = GenerateMigrationAttemptId();
    ASSERT_EQ(first.size(), 32U);
    EXPECT_EQ(second.size(), 32U);
    EXPECT_NE(first, second);
    for (const char value : first) {
        EXPECT_TRUE((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'));
    }
}

TEST(MigrationReplayCacheTest, ReplaysCompletedResultWithoutExecutingAgain)
{
    MigrationReplayCache cache;
    auto first = cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "request-a");
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    ASSERT_TRUE(cache.Complete(first, "reply-a"));

    auto repeated = cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "request-a");
    EXPECT_EQ(repeated.decision, MigrationReplayCache::Decision::Replay);
    EXPECT_EQ(repeated.reply, "reply-a");
}

TEST(MigrationReplayCacheTest, RejectsChangedPayloadAndConcurrentDuplicate)
{
    MigrationReplayCache cache;
    auto first = cache.Begin("attempt-1", MigrationReplayCache::Step::Transfer, "cipher-a");
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    EXPECT_EQ(cache.Begin("attempt-1", MigrationReplayCache::Step::Transfer, "cipher-a").decision,
              MigrationReplayCache::Decision::InProgress);
    EXPECT_EQ(cache.Begin("attempt-1", MigrationReplayCache::Step::Transfer, "cipher-b").decision,
              MigrationReplayCache::Decision::Conflict);
    ASSERT_TRUE(cache.Complete(first, "ok"));
    EXPECT_EQ(cache.Begin("attempt-1", MigrationReplayCache::Step::Transfer, "cipher-b").decision,
              MigrationReplayCache::Decision::Conflict);
}

TEST(MigrationReplayCacheTest, BoundsEntriesAndExpiresCompletedOnes)
{
    using Clock = MigrationReplayCache::Clock;
    const auto start = Clock::now();
    MigrationReplayCache cache(1, 128, std::chrono::seconds(10));
    auto first = cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "req", start);
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    EXPECT_EQ(cache.Begin("attempt-2", MigrationReplayCache::Step::Prepare, "req", start).decision,
              MigrationReplayCache::Decision::Capacity);
    ASSERT_TRUE(cache.Complete(first, "reply", start));
    EXPECT_EQ(cache.Begin("attempt-2", MigrationReplayCache::Step::Prepare, "req",
                          start + std::chrono::seconds(11)).decision,
              MigrationReplayCache::Decision::Execute);
}

TEST(MigrationReplayCacheTest, NeverEvictsInFlightAndRejectsOversizedPayload)
{
    MigrationReplayCache cache(1, 8, std::chrono::seconds(1));
    auto first = cache.Begin("a", MigrationReplayCache::Step::Prepare, "1234");
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    EXPECT_EQ(cache.Begin("b", MigrationReplayCache::Step::Prepare, "x").decision,
              MigrationReplayCache::Decision::Capacity);
    EXPECT_EQ(cache.Begin("c", MigrationReplayCache::Step::Prepare, "123456789").decision,
              MigrationReplayCache::Decision::Capacity);
}

TEST(MigrationReplayCacheTest, OversizedReplyLeavesUnreplayableTombstone)
{
    MigrationReplayCache cache(1, 10, std::chrono::seconds(10));
    auto first = cache.Begin("a", MigrationReplayCache::Step::Finish, "1234");
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    EXPECT_FALSE(cache.Complete(first, "123456"));
    EXPECT_EQ(cache.Begin("a", MigrationReplayCache::Step::Finish, "1234").decision,
              MigrationReplayCache::Decision::Unavailable);
}

TEST(MigrationReplayCacheTest, CompletedStageRemainsReplayableWhileAttemptIsActive)
{
    using Clock = MigrationReplayCache::Clock;
    const auto start = Clock::now();
    bool active = true;
    MigrationReplayCache cache(1, 128, std::chrono::seconds(10),
                               [&](const std::string &id) { return active && id == "attempt-1"; });
    auto first = cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "req", start);
    ASSERT_EQ(first.decision, MigrationReplayCache::Decision::Execute);
    ASSERT_TRUE(cache.Complete(first, "reply", start));
    EXPECT_EQ(cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "req",
                          start + std::chrono::seconds(11)).decision,
              MigrationReplayCache::Decision::Replay);
    active = false;
    EXPECT_EQ(cache.Begin("attempt-1", MigrationReplayCache::Step::Prepare, "req",
                          start + std::chrono::seconds(11)).decision,
              MigrationReplayCache::Decision::Execute);
}

TEST(MigrationReplayCacheTest, FinalQueryDistinguishesInProgressSuccessAndWrongIdentity)
{
    using Cache = MigrationReplayCache;
    const auto now = Cache::Clock::now();
    Cache cache;
    auto admission = cache.Begin("attempt-1", Cache::Step::Finish, "request", now, "uuid-1");
    ASSERT_EQ(admission.decision, Cache::Decision::Execute);
    EXPECT_EQ(cache.QueryFinal("uuid-1", "attempt-1", now).state, Cache::FinalState::InProgress);
    EXPECT_EQ(cache.QueryFinal("uuid-2", "attempt-1", now).state, Cache::FinalState::Unknown);

    ASSERT_TRUE(cache.Complete(admission, "reply", now, true));
    const auto result = cache.QueryFinal("uuid-1", "attempt-1", now);
    EXPECT_EQ(result.state, Cache::FinalState::CompletedSuccess);
    EXPECT_EQ(result.reply, "reply");
}

TEST(MigrationReplayCacheTest, FinalQueryKeepsExplicitFailureButNotUnreplayableResult)
{
    using Cache = MigrationReplayCache;
    const auto now = Cache::Clock::now();
    Cache cache(2, 128, std::chrono::seconds(10));
    auto failed = cache.Begin("attempt-1", Cache::Step::Finish, "request", now, "uuid-1");
    ASSERT_TRUE(cache.Complete(failed, "failure-reply", now, false));
    EXPECT_EQ(cache.QueryFinal("uuid-1", "attempt-1", now).state, Cache::FinalState::CompletedFailure);

    auto unknown = cache.Begin("attempt-2", Cache::Step::Finish, "request", now, "uuid-1");
    cache.CompleteUnreplayable(unknown, now);
    EXPECT_EQ(cache.QueryFinal("uuid-1", "attempt-2", now).state, Cache::FinalState::Unknown);
    EXPECT_EQ(cache.QueryFinal("uuid-1", "attempt-1", now + std::chrono::seconds(11)).state,
              Cache::FinalState::Unknown);
}

TEST(MigrationReplayCacheTest, FinalQueryNeverTreatsMissingOutcomeAsSuccess)
{
    using Cache = MigrationReplayCache;
    const auto now = Cache::Clock::now();
    Cache cache;
    auto admission = cache.Begin("attempt-1", Cache::Step::Finish, "request", now, "uuid-1");
    ASSERT_TRUE(cache.Complete(admission, "default-zero-reply", now));
    EXPECT_EQ(cache.QueryFinal("uuid-1", "attempt-1", now).state, Cache::FinalState::Unknown);
}

} // namespace
} // namespace virtrust
