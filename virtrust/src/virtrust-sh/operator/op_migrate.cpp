// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_migrate.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {
namespace {
constexpr int OP_MIGRATE_EXTRA_CMD_NUM = 2;
}

OpRc OpMigrate::Exec()
{
    // CLI 在打开 libvirt 连接之前拒绝远端源，避免无效请求也触达其他节点。
    if (!IsLocalMigrationSourceUri(config_.uri)) {
        VIRTRUST_LOG_ERROR("Unsupported migration source URI: {}", config_.uri);
        return OpRc::ERROR;
    }
    // make connection
    conn_.reset();
    conn_ = std::make_unique<ConnCtx>();
    if (!conn_->SetUri(config_.uri)) {
        VIRTRUST_LOG_ERROR("Failed to set uri: {}", config_.uri);
        return OpRc::ERROR;
    }
    conn_->Connect();
    if (conn_->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Failed to establish connection to: {}", config_.uri);
        return OpRc::ERROR;
    }
    // API 返回业务最终状态及错误证据；命令行不再从日志反推迁移是否完成。
    const auto result = DomainMigrate(conn_, domainName_, destUri_, flags_);
    // Busy 继续由主命令统一提示“未开始”；其他迁移失败只输出结构化的固定字段。
    if (result.rc != VirtrustRc::OK && result.rc != VirtrustRc::BUSY) {
        fmt::print(stderr, "{}\n", FormatMigrationResult(result));
    }
    return ParseVirtrustRc(result.rc);
}

// Parse the args from command line
OpRc OpMigrate::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1; // reset

    std::vector<option> opt = {{"help", no_argument, nullptr, 'h'}, {nullptr, 0, nullptr, 0}};

    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+h", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::OK;
            default:
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::ERROR;
        }
    }

    // 迁移成功后删除源端虚机
    flags_ |= MIGRATE_UNDEFINE_SOURCE;

    if (argc - optind != OP_MIGRATE_EXTRA_CMD_NUM) {
        fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n", OP_MIGRATE_EXTRA_CMD_NUM, argc - optind);
        PrintUsage();
        return OpRc::ERROR;
    }

    if (strlen(argv[optind]) != 0) {
        domainName_ = argv[optind];
    } else {
        VIRTRUST_LOG_ERROR("Invalid empty domain name");
        return OpRc::ERROR;
    }

    if (strlen(argv[optind + 1]) != 0) {
        destUri_ = argv[optind + 1];
    } else {
        VIRTRUST_LOG_ERROR("Invalid empty domain name");
        return OpRc::ERROR;
    }
    return OpRc::OK;
}

// Print the usage of this operator
void OpMigrate::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    migrate - migrate domain to another host\n"
               "\n"
               "  SYNOPSIS:\n"
               "    migrate <domain> <desturi>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "\n");
}

} // namespace virtrust
