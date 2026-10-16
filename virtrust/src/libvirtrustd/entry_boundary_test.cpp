/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include <gtest/gtest.h>

#include <cstdio>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>

#include "libvirtrustd/entry_boundary.h"

namespace virtrust {
namespace {
TEST(EntryBoundaryTest, PreservesNormalReturnCode)
{
    for (int code : {0, 1, 7}) {
        EXPECT_EQ(RunEntryBoundary(code, nullptr, [](int value, char **, const char *&) { return value; }), code);
    }
}

// 临时文件捕获诊断，不替换进程标准错误，提前退出时自动关闭。
TEST(EntryBoundaryTest, ClassifiesExceptionsAndReportsStage)
{
    const char *expected[] = {"Out of memory", "injected failure", "Unknown exception"};
    for (int kind = 0; kind < 3; ++kind) {
        SCOPED_TRACE(kind);
        const auto closeFile = [](FILE *file) { std::fclose(file); };
        std::unique_ptr<FILE, decltype(closeFile)> output(std::tmpfile(), closeFile);
        ASSERT_NE(output, nullptr);
        const int result = RunEntryBoundary(
            kind, nullptr,
            [](int value, char **, const char *&stage) -> int {
                stage = "configuration loading";
                if (value == 0) {
                    throw std::bad_alloc();
                }
                if (value == 1) {
                    throw std::runtime_error("injected failure");
                }
                throw 42;
            },
            fileno(output.get()));
        EXPECT_EQ(result, 1);
        ASSERT_EQ(std::fseek(output.get(), 0, SEEK_SET), 0);
        char buffer[512]{};
        const auto length = std::fread(buffer, 1, sizeof(buffer), output.get());
        const std::string text(buffer, length);
        EXPECT_NE(text.find("configuration loading"), std::string::npos);
        EXPECT_NE(text.find(expected[kind]), std::string::npos);
    }
}

TEST(EntryBoundaryTest, OutputFailureStillReturnsFailureAndUnwindsLocals)
{
    bool destroyed = false;
    // 通过argv携带测试上下文，不引入会分配内存的函数包装器。
    char *context[] = {reinterpret_cast<char *>(&destroyed)};
    EXPECT_EQ(RunEntryBoundary(
                  0, context,
                  [](int, char **argv, const char *&) -> int {
                      struct Guard {
                          bool *flag;
                          ~Guard()
                          {
                              *flag = true;
                          }
                      } guard{reinterpret_cast<bool *>(argv[0])};
                      throw std::runtime_error("injected failure");
                  },
                  -1),
              1);
    EXPECT_TRUE(destroyed);
}
} // 匿名命名空间
} // 命名空间 virtrust
