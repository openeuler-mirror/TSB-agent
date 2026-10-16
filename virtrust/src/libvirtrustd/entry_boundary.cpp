/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#include "libvirtrustd/entry_boundary.h"

#include <unistd.h>

#include <cstring>
#include <exception>
#include <new>

namespace virtrust {
namespace {
// 不依赖日志初始化或动态字符串；单次尽力写入，不重试失败或承诺输出完整。
void WriteText(int fd, const char *text) noexcept
{
    if (text != nullptr) {
        const auto written = write(fd, text, std::strlen(text));
        (void)written;
    }
}

void ReportFailure(int fd, const char *stage, const char *detail) noexcept
{
    WriteText(fd, "Daemon entry failed [");
    WriteText(fd, stage);
    WriteText(fd, "]: ");
    WriteText(fd, detail);
    WriteText(fd, "\n");
}
} // 匿名命名空间

int RunEntryBoundary(int argc, char **argv, EntryFunction entry, int diagnosticFd) noexcept
{
    const char *stage = "entry";
    try {
        return entry(argc, argv, stage);
    } catch (const std::bad_alloc &) {
        ReportFailure(diagnosticFd, stage, "Out of memory");
    } catch (const std::exception &error) {
        ReportFailure(diagnosticFd, stage, error.what());
    } catch (...) {
        ReportFailure(diagnosticFd, stage, "Unknown exception");
    }
    return 1;
}
} // 命名空间 virtrust
