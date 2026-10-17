/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "virtrust/api/create_connection_args.h"

namespace virtrust {
TEST(CreateConnectionArgsTest, KeepsCandidatesInOrderAndRemovesConnectionOptions)
{
    const std::vector<std::string> args = {
        "/usr/bin/virt-install", "--name", "VM", "--connect", "first", "-csecond", "--memory", "1024"};
    const auto parsed = ParseCreateConnectionArgs(args);

    EXPECT_TRUE(parsed.hasExplicitOption);
    EXPECT_EQ(parsed.candidates, (std::vector<std::string>{"first", "second"}));
    EXPECT_EQ(parsed.argsWithoutConnection,
              (std::vector<std::string>{"/usr/bin/virt-install", "--name", "VM", "--memory", "1024"}));
}

TEST(CreateConnectionArgsTest, RetainsInvalidCandidatePositionWithoutConsumingNextOption)
{
    const std::vector<std::string> args = {
        "/usr/bin/virt-install", "--connect", "--name", "VM", "--connect=", "-c", "last"};
    const auto parsed = ParseCreateConnectionArgs(args);

    EXPECT_TRUE(parsed.hasExplicitOption);
    EXPECT_EQ(parsed.candidates, (std::vector<std::string>{"", "", "last"}));
    EXPECT_EQ(parsed.argsWithoutConnection, (std::vector<std::string>{"/usr/bin/virt-install", "--name", "VM"}));
}

TEST(CreateConnectionArgsTest, AcceptsLibvirtAliasButRejectsEmptyOversizeAndControlBytes)
{
    EXPECT_TRUE(IsUsableConnectionCandidate("local_alias"));
    EXPECT_FALSE(IsUsableConnectionCandidate(""));
    EXPECT_FALSE(IsUsableConnectionCandidate(std::string(1025, 'x')));
    EXPECT_FALSE(IsUsableConnectionCandidate(std::string("a\nb")));
}

TEST(CreateConnectionArgsTest, NoExplicitOptionKeepsArguments)
{
    const std::vector<std::string> args = {"/usr/bin/virt-install", "--name", "VM"};
    const auto parsed = ParseCreateConnectionArgs(args);
    EXPECT_FALSE(parsed.hasExplicitOption);
    EXPECT_TRUE(parsed.candidates.empty());
    EXPECT_EQ(parsed.argsWithoutConnection, args);
}
} // namespace virtrust
