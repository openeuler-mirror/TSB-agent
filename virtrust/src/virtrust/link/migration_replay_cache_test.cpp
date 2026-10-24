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

} // namespace
} // namespace virtrust
