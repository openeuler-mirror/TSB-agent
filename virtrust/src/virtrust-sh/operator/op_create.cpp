// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_create.h"

#include <getopt.h>

#include <algorithm>
#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/create_connection_args.h"
#include "virtrust/api/domain.h"

namespace virtrust {

OpRc OpCreate::Exec()
{
    const auto parsed = ParseCreateConnectionArgs(virtInstallArgs_);
    // 主命令候选始终排在 create 子命令候选之前；各组内部保留用户输入顺序。
    std::vector<std::string> candidates = config_.uriCandidates;
    candidates.insert(candidates.end(), parsed.candidates.begin(), parsed.candidates.end());
    // 只有完全没有显式连接选项时才尝试项目默认 URI。
    if (candidates.empty() && config_.uriCandidates.empty() && !parsed.hasExplicitOption) {
        candidates.push_back(config_.uri);
    }

    conn_.reset();
    // 连接失败可换下一个候选；每次使用新对象，避免失败句柄或 URI 状态相互污染。
    for (const auto &candidate : candidates) {
        if (!IsUsableConnectionCandidate(candidate)) {
            VIRTRUST_LOG_ERROR("Skipping invalid create connection URI.");
            continue;
        }
        auto attempt = std::make_unique<ConnCtx>();
        if (!attempt->SetUri(candidate) || !attempt->Connect()) {
            VIRTRUST_LOG_ERROR("Failed to establish create connection to: {}", candidate);
            continue;
        }
        conn_ = std::move(attempt);
        config_.uri = candidate;
        // 连接已经选定，后续业务失败也不能改选另一台宿主机重试。
        break;
    }
    if (conn_ == nullptr) {
        VIRTRUST_LOG_ERROR("No create connection URI could be opened.");
        return OpRc::ERROR;
    }
    // 删除所有原始连接选项，只把选中 URI 传给 API 和 virt-install 子进程。
    auto createArgs = parsed.argsWithoutConnection;
    const auto optionEnd = std::find(createArgs.begin(), createArgs.end(), "--");
    createArgs.insert(optionEnd, {"--connect", conn_->GetUri()});
    return ParseVirtrustRc(DomainCreate(conn_, createArgs));
}

// Parse the args from command line
OpRc OpCreate::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1; // reset
    bool hasNameArg = false;

    std::vector<option> opt = {
        {"help", no_argument, nullptr, 'h'}, {"name", required_argument, nullptr, 'n'}, {nullptr, 0, nullptr, 0}};

    opterr = 0;
    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = 1;
                return OpRc::OK;
            case 'n':
                hasNameArg = true;
                break;
            default:
                continue; // do nothing;
        }
    }

    opterr = 1;
    if (!hasNameArg) {
        fmt::print("\n--name/-n not set.\n");
        return OpRc::ERROR;
    }

    virtInstallArgs_.clear();

    // all args should be parse to virt-install, so nothing need to be done here
    virtInstallArgs_.emplace_back(VIRTRUST_SH_VIRT_INSTALL_PATH);
    for (auto i = 1; i < argc; ++i) {
        virtInstallArgs_.emplace_back(argv[i]);
    }
    return OpRc::OK;
}

// Print the usage of this operator
void OpCreate::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    create - create a new virtual machine\n"
               "\n"
               "  SYNOPSIS:\n"
               "    create <args>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "\n"
               "  ARGS:\n"
               "    virt-install args, see all supported args with `virt-install "
               "--help`.\n"
               "\n");
}

} // namespace virtrust
