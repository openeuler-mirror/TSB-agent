/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "virtrust-sh/operator/op_migration_result.h"

#include <unistd.h>

#include <string>

#include "spdlog/fmt/fmt.h"

#include "virtrust/api/domain.h"
#include "virtrust/link/migration_attempt_id.h"
#include "virtrust/link/migration_destination_uri.h"
#include "virtrust/link/migration_result.h"

namespace virtrust {
namespace {

bool ValidUuid(const std::string &uuid)
{
    if (uuid.size() != 36) {
        return false;
    }
    for (size_t index = 0; index < uuid.size(); ++index) {
        const char value = uuid[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value != '-') {
                return false;
            }
        } else if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
                     (value >= 'A' && value <= 'F'))) {
            return false;
        }
    }
    return true;
}

} // namespace

OpRc OpMigrationResult::ParseArgv(int argc, char **argv)
{
    if (argc != 4 || argv == nullptr || argv[1] == nullptr || argv[2] == nullptr || argv[3] == nullptr) {
        PrintUsage();
        return OpRc::ERROR;
    }
    std::string ip;
    if (!ValidUuid(argv[1]) || !ParseMigrationDestinationUri(argv[2], ip) ||
        !ValidMigrationAttemptId(argv[3])) {
        fmt::print(stderr, "Invalid migration result query arguments.\n");
        return OpRc::ERROR;
    }
    uuid_ = argv[1];
    destUri_ = argv[2];
    attemptId_ = argv[3];
    return OpRc::OK;
}

OpRc OpMigrationResult::Exec()
{
    // 本机 UDS 由守护进程转发节点间查询；不打开 libvirt、不取得迁移资格。
    if (geteuid() != 0) {
        fmt::print(stderr, "Migration result query requires root.\n");
        return OpRc::ERROR;
    }
    try {
        const auto result = DomainQueryMigrationFinalResult(uuid_, destUri_, attemptId_);
        switch (result.state) {
            case MigrationFinalState::CompletedSuccess:
                fmt::print("Destination final result: COMPLETED_SUCCESS. Verify source cleanup separately.\n");
                return OpRc::OK;
            case MigrationFinalState::CompletedFailure:
                fmt::print(stderr, "Destination final result: COMPLETED_FAILURE.\n");
                if (result.hasDiagnostic) {
                    fmt::print(stderr, "{}\n", FormatMigrationResult(result.diagnostic));
                }
                return OpRc::ERROR;
            case MigrationFinalState::InProgress:
                fmt::print(stderr, "Destination final result: IN_PROGRESS. Query later; do not retry migration.\n");
                return OpRc::ERROR;
            case MigrationFinalState::Unknown:
                fmt::print(stderr, "Destination final result: UNKNOWN. Verify both nodes before retrying.\n");
                return OpRc::ERROR;
        }
    } catch (...) {
        fmt::print(stderr, "Migration result query failed. Verify both nodes before retrying.\n");
    }
    return OpRc::ERROR;
}

void OpMigrationResult::PrintUsage()
{
    fmt::print("migration-result <uuid> <desturi> <attempt-id>\n");
}

} // namespace virtrust
