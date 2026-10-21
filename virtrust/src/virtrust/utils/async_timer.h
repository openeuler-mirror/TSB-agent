/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace virtrust {
// Cancel 唤醒并取消仍在等待的任务，不等待回调退出。
// 已到期退出等待的回调仍可能在 Cancel 返回后执行；调用方须校验代数及对象寿命。
class AsyncTimer {
public:
    AsyncTimer() = default;

    ~AsyncTimer()
    {
        Cancel();
    }

    // 启动一个异步计时器，timeout后执行callback
    void Start(std::chrono::microseconds timeout, std::function<void()> callback)
    {
        auto next = std::make_shared<TimerState>();
        {
            std::lock_guard<std::mutex> guard(mutex_);
            CancelState(active_);
            active_ = next;
        }
        try {
            // 线程只持有独立状态，不访问 AsyncTimer；析构或取消无需等待可能被业务锁阻塞的回调。
            std::thread([next, timeout, callback = std::move(callback)]() mutable {
                std::unique_lock<std::mutex> guard(next->mutex);
                if (next->condition.wait_for(guard, timeout, [&] { return next->canceled; })) {
                    return;
                }
                guard.unlock();
                callback();
            }).detach();
        } catch (...) {
            CancelState(next);
            throw;
        }
    }

    // 取消定时器
    void Cancel()
    {
        std::lock_guard<std::mutex> guard(mutex_);
        CancelState(active_);
        active_.reset();
    }

private:
    struct TimerState {
        std::mutex mutex;
        std::condition_variable condition;
        bool canceled = false;
    };

    static void CancelState(const std::shared_ptr<TimerState> &state)
    {
        if (!state) {
            return;
        }
        {
            std::lock_guard<std::mutex> guard(state->mutex);
            state->canceled = true;
        }
        state->condition.notify_all();
    }

    std::mutex mutex_;
    std::shared_ptr<TimerState> active_;
};

} // namespace virtrust
