/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include "virtrust/utils/async_timer.h"

namespace virtrust {
TEST(AsyncTimerLifecycleTest, CancelReturnsWhileCallbackIsRunning)
{
    struct CallbackState {
        std::promise<void> started;
        std::promise<void> done;
        std::atomic<bool> release{false};
    };
    auto state = std::make_shared<CallbackState>();
    auto started = state->started.get_future();
    auto done = state->done.get_future();
    AsyncTimer timer;
    // 回调独立持有状态；即使启动等待超时，提前退出也不会留下悬空栈引用。
    timer.Start(std::chrono::microseconds(0), [state] {
        state->started.set_value();
        while (!state->release.load()) {
            std::this_thread::yield();
        }
        state->done.set_value();
    });
    const auto startOutcome = started.wait_for(std::chrono::seconds(2));
    if (startOutcome != std::future_status::ready) {
        state->release.store(true);
        timer.Cancel();
        FAIL() << "Timer callback did not start within two seconds";
    }

    std::promise<void> cancelDone;
    auto canceled = cancelDone.get_future();
    std::thread cancelThread([&] {
        timer.Cancel();
        cancelDone.set_value();
    });
    // 先检查 Cancel 是否返回，再放行回调；旧版 join 实现会超时但仍可安全收尾。
    const auto cancelOutcome = canceled.wait_for(std::chrono::seconds(2));
    state->release.store(true);
    cancelThread.join();
    EXPECT_EQ(cancelOutcome, std::future_status::ready);
    EXPECT_EQ(done.wait_for(std::chrono::seconds(2)), std::future_status::ready);
}
} // 命名空间 virtrust
