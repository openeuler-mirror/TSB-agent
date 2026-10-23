/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/link/grpc_client.h"

#include <grpcpp/grpcpp.h>

#include <memory>
#include <string>

#include "virtrust/base/str_utils.h"
#include "virtrust/link/defines.h"

namespace virtrust {
namespace {
// 当前 UDS 调用没有可信业务回复时，结果只能是未知且需要人工核查。
MigrationResult UnknownUdsFailure(MigrationErrorOrigin origin)
{
    MigrationResult result;
    result.primaryError = {MigrationStage::Uds, MigrationSide::Source, MigrationOperation::NotifyPeer,
                           origin, false, 0};
    result.hasPrimaryError = true;
    return result;
}

bool IsKnownBusinessResult(uint32_t value)
{
    switch (static_cast<VirtrustRc>(value)) {
        case VirtrustRc::OK:
        case VirtrustRc::ERROR:
        case VirtrustRc::CHECK_FAILED:
        case VirtrustRc::INCONSISTENT_RESOURCE:
        case VirtrustRc::BUSY:
            return true;
        default:
            return false;
    }
}
} // namespace

UdsClient::UdsClient(LinkConfig config) : config_(config)
{}

MigrationResult UdsClient::DomainMigrate(const MigrationConfig &config)
{
    // CLI/API 只与本机守护进程通信；此请求会同步等待源端会话的最终返回。
    protos::DomainMigraterRequest request;
    request.set_domainname(config.domainName);
    request.set_uuid(config.uuid);
    request.set_desturi(config.destUri);
    request.set_localuri(config.localUri);
    request.set_flags(config.flags);
    // 业务回复只有在 gRPC 状态成功且诊断存在时才可采信。
    protos::DomainMigraterReply reply;

    // 本机 UDS 调用上下文。
    grpc::ClientContext context;

    // Unix socket 是本机入口；节点之间的迁移 RPC 由守护进程继续发起。
    std::shared_ptr<grpc::Channel> channel =
        grpc::CreateChannel("unix:" + config_.udsPath, grpc::InsecureChannelCredentials());

    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);
    if (stub == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|new stub failed");
        return UnknownUdsFailure(MigrationErrorOrigin::Internal);
    }
    grpc::Status status = stub->DomainMigrate(&context, request, &reply);

    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|fail to triggle DomainMigrate:{}, serverAddress is: {}",
                           status.error_message(), config_.udsPath);
        // UDS 未取得有效业务回复，不允许读取 reply 的默认成功值。
        return UnknownUdsFailure(MigrationErrorOrigin::Grpc);
    }
    if (!reply.has_diagnostic()) {
        // 所有节点均应使用当前协议；缺少诊断的空成功回复不能被采信。
        return UnknownUdsFailure(MigrationErrorOrigin::Internal);
    }
    // result 是兼容现有业务分支的数值码，diagnostic 承载阶段与副作用证据。
    const bool knownBusinessResult = IsKnownBusinessResult(reply.result());
    auto result = FromProto(reply.diagnostic(), knownBusinessResult ? static_cast<VirtrustRc>(reply.result())
                                                                 : VirtrustRc::ERROR);
    // Busy 只能表示准入前拒绝；数值码和诊断互相矛盾时，不能压掉可能已发生的副作用。
    const bool contradictoryBusy = result.rc == VirtrustRc::BUSY &&
        (result.outcome != MigrationOutcome::FailedBeforeEffect || result.manualCheckRequired ||
         result.confirmedSteps != 0 || !result.compensationErrors.empty());
    if (!knownBusinessResult || contradictoryBusy ||
        (result.rc == VirtrustRc::OK && result.outcome != MigrationOutcome::Success)) {
        result.rc = VirtrustRc::ERROR;
        result.outcome = MigrationOutcome::Unknown;
        result.manualCheckRequired = true;
    }
    if (result.rc != VirtrustRc::OK && !result.hasPrimaryError) {
        // 有失败码却缺根因时不能宣称“未开始”或“已部分完成”。
        result.primaryError = {MigrationStage::Uds, MigrationSide::Source, MigrationOperation::NotifyPeer,
                               MigrationErrorOrigin::Internal, false, 0};
        result.hasPrimaryError = true;
        result.outcome = MigrationOutcome::Unknown;
        result.manualCheckRequired = true;
    }
    return result;
}

RpcClient::RpcClient(LinkConfig config) : config_(config)
{}

int32_t RpcClient::PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest &request,
                                    protos::PrepareMigReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|PrepareMigration|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    auto channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->PrepareMigration(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|fail to triggle prepare migration:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 2: 交换公钥
int32_t RpcClient::ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                       protos::EXchangePkAndReportReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|ExchangePkAndReport|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->ExchangePkAndReport(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR(
            "|ExchangePkAndReport|END|returnF|fail to triggle exchange pkandReport:{}, serverAddress is: {}",
            status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 3: 开始迁移
int32_t RpcClient::StartMigration(uint32_t timeout, const protos::StartMigRequest &request,
                                  protos::StartMigReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|StartMigration|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->StartMigration(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|fail to triggle start migration:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 4：迁移虚机密码资源
int32_t RpcClient::SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                                    protos::VRsourceInfoReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|SendVRsourceData|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->SendVRsourceData(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF|fail to triggle send vrsourceData:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 5: 通知迁移结果
int32_t RpcClient::NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                         protos::MigrateResultReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|NotifyVRMigrateResult|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->NotifyVRMigrateResult(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR(
            "|NotifyVRMigrateResult|END|returnF|fail to triggle NotifyVRMigrateResult :{}, serverAddress is: {}",
            status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}
}; // namespace virtrust
