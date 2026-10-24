/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/link/grpc_client.h"

#include <grpcpp/grpcpp.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <utility>

#include "virtrust/base/str_utils.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/migration_attempt_id.h"

namespace virtrust {
namespace {
// 当前 UDS 调用没有可信业务回复时，结果只能是未知且需要人工核查。
MigrationResult UnknownUdsFailure(MigrationErrorOrigin origin, const std::string &attemptId = {})
{
    MigrationResult result;
    if (ValidMigrationAttemptId(attemptId)) {
        result.attemptId = attemptId;
    }
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

// 节点间 RPC 共用同一期限策略；总期限覆盖所有调用和退避，而不是每次重试重新计时。
template <typename Reply, typename Call, typename Result>
int32_t InvokePeerWithRetry(const LinkConfig &config, uint32_t timeout, const char *operation,
                            Reply *response, Call &&call, Result &&result)
{
    if (response == nullptr || timeout == 0) {
        VIRTRUST_LOG_ERROR("{}: invalid reply or zero timeout", operation);
        return RPC_TRANSPORT_FAILURE;
    }
    const std::string serverAddress = config.ip + ":" + std::to_string(config.port);
    // 凭证和连接端点在本阶段只创建一次；重试只新建一次性 ClientContext。
    auto credentials = grpc::InsecureChannelCredentials();
    if (!config.caPath.empty() && !config.certPath.empty() && !config.skPath.empty()) {
        grpc::SslCredentialsOptions options;
        options.pem_root_certs = ReadFile(config.caPath);
        options.pem_private_key = ReadFile(config.skPath);
        options.pem_cert_chain = ReadFile(config.certPath);
        credentials = grpc::SslCredentials(options);
    }
    const auto channel = grpc::CreateChannel(serverAddress, credentials);
    auto stub = protos::MigrationService::NewStub(channel);
    if (stub == nullptr) {
        VIRTRUST_LOG_ERROR("{}: could not create gRPC stub", operation);
        return RPC_TRANSPORT_FAILURE;
    }

    // 使用单调时钟计算总预算，防止退避及多次 RPC 各自获得完整的 5/20 秒。
    const auto stageDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    // JSON 入口已做严格校验；这里再次限界以约束直接构造 LinkConfig 的调用方。
    const auto attempts = std::clamp<uint16_t>(config.rpcRetryMaxAttempts, 1, MAX_RPC_RETRY_MAX_ATTEMPTS);
    const auto initialBackoff = std::clamp<uint16_t>(config.rpcRetryInitialBackoffMs, 1,
                                                   MAX_RPC_RETRY_INITIAL_BACKOFF_MS);
    const auto maxBackoff = std::clamp<uint16_t>(config.rpcRetryMaxBackoffMs, initialBackoff,
                                               MAX_RPC_RETRY_MAX_BACKOFF_MS);
    uint32_t nextBackoff = initialBackoff;
    // networkFailures 只计一般 UNAVAILABLE；目的端明确“处理中”不消耗重试次数。
    // requestCount 计实际发送次数，供期限耗尽和失败日志定位。
    uint16_t networkFailures = 0;
    uint32_t requestCount = 0;
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= stageDeadline) {
            VIRTRUST_LOG_ERROR("{}: stage deadline exhausted before request {}", operation, requestCount + 1);
            break;
        }
        // gRPC 的 ClientContext 只能使用一次；重试新建上下文，但请求对象和尝试身份始终不变。
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + (stageDeadline - now));
        response->Clear();
        ++requestCount;
        const grpc::Status status = call(*stub, context, response);
        // 只有收到成功的 gRPC 回复才提取业务值；空值表示最终结果仍在处理中。
        const auto value = status.ok() ? result(*response) : std::optional<int32_t>{};
        if (status.ok() && value.has_value()) {
            return *value;
        }
        // 目的端已明确确认原请求仍在执行：仅在阶段总期限内轮询，不耗尽网络失败的次数配额。
        // 普通 UNAVAILABLE 没有专用 details，按网络失败计数，不能无限重发。
        const bool inProgress = (status.ok() && !value.has_value()) ||
                                (status.error_code() == grpc::StatusCode::UNAVAILABLE &&
                                 status.error_details() == MIGRATION_STEP_IN_PROGRESS_DETAIL);
        // 业务失败、协议冲突或不可回放均不是本阶段可自动修复的网络抖动。
        if ((!status.ok() && status.error_code() != grpc::StatusCode::UNAVAILABLE) ||
            (!inProgress && ++networkFailures >= attempts)) {
            VIRTRUST_LOG_ERROR("{}: gRPC failed after {} request(s), code={}, detail={}", operation, requestCount,
                               static_cast<int>(status.error_code()), status.error_message());
            return RPC_TRANSPORT_FAILURE;
        }
        const auto remaining = stageDeadline - std::chrono::steady_clock::now();
        // 发送失败后再次检查剩余时间，已到期就停止
        if (remaining <= std::chrono::steady_clock::duration::zero()) {
            VIRTRUST_LOG_ERROR("{}: stage deadline exhausted after {} request(s)", operation, requestCount);
            return RPC_TRANSPORT_FAILURE;
        }
        // 与 gRPC 官方策略相同，对指数退避加入 ±20% 抖动以降低多个节点同时重试的冲击。
        thread_local std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<uint32_t> jitter(nextBackoff * 80 / 100, nextBackoff * 120 / 100);
        const auto delay = std::min(std::chrono::milliseconds(jitter(generator)),
                                    std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
        VIRTRUST_LOG_WARN("{}: gRPC unavailable; retrying request {} after {} ms", operation, requestCount + 1,
                          delay.count());
        std::this_thread::sleep_for(delay);
        nextBackoff = std::min(nextBackoff * 2, static_cast<uint32_t>(maxBackoff));
    }
    return RPC_TRANSPORT_FAILURE;
}

template <typename Reply, typename Call>
int32_t InvokePeerWithRetry(const LinkConfig &config, uint32_t timeout, const char *operation,
                            Reply *response, Call &&call)
{
    return InvokePeerWithRetry(config, timeout, operation, response, std::forward<Call>(call),
                               [](const Reply &reply) -> std::optional<int32_t> { return reply.result(); });
}
} // namespace

UdsClient::UdsClient(LinkConfig config) : config_(config)
{}

MigrationFinalQueryResult UdsClient::QueryMigrationFinalResult(const std::string &uuid,
                                                               const std::string &destUri,
                                                               const std::string &attemptId)
{
    protos::QueryMigrationFinalResultRequest request;
    request.set_uuid(uuid);
    request.set_attempt_id(attemptId);
    request.set_dest_uri(destUri);
    protos::QueryMigrationFinalResultReply reply;
    grpc::ClientContext context;
    // 本机转发可额外使用五秒节点查询预算；为 UDS 调用留出少量调度余量。
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(7));
    const auto channel = grpc::CreateChannel("unix:" + config_.udsPath, grpc::InsecureChannelCredentials());
    auto stub = protos::MigrationService::NewStub(channel);
    if (stub == nullptr || !stub->DomainQueryMigrationFinalResult(&context, request, &reply).ok()) {
        return {};
    }
    MigrationFinalQueryResult result;
    switch (reply.state()) {
        case protos::FINAL_RESULT_IN_PROGRESS: result.state = MigrationFinalState::InProgress; break;
        case protos::FINAL_RESULT_COMPLETED_SUCCESS: result.state = MigrationFinalState::CompletedSuccess; break;
        case protos::FINAL_RESULT_COMPLETED_FAILURE:
            result.state = MigrationFinalState::CompletedFailure;
            if (reply.has_diagnostic()) {
                result.diagnostic = FromProto(reply.diagnostic(), VirtrustRc::ERROR);
                result.hasDiagnostic = true;
            }
            break;
        case protos::FINAL_RESULT_UNKNOWN:
        default: break;
    }
    return result;
}

MigrationResult UdsClient::DomainMigrate(const MigrationConfig &config)
{
    // CLI/API 只与本机守护进程通信；此请求会同步等待源端会话的最终返回。
    protos::DomainMigraterRequest request;
    request.set_domainname(config.domainName);
    request.set_uuid(config.uuid);
    request.set_desturi(config.destUri);
    request.set_localuri(config.localUri);
    request.set_flags(config.flags);
    request.set_attempt_id(config.attemptId);
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
        return UnknownUdsFailure(MigrationErrorOrigin::Internal, config.attemptId);
    }
    grpc::Status status = stub->DomainMigrate(&context, request, &reply);

    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|fail to triggle DomainMigrate:{}, serverAddress is: {}",
                           status.error_message(), config_.udsPath);
        // UDS 未取得有效业务回复，不允许读取 reply 的默认成功值。
        return UnknownUdsFailure(MigrationErrorOrigin::Grpc, config.attemptId);
    }
    if (!reply.has_diagnostic()) {
        // 所有节点均应使用当前协议；缺少诊断的空成功回复不能被采信。
        return UnknownUdsFailure(MigrationErrorOrigin::Internal, config.attemptId);
    }
    // result 是兼容现有业务分支的数值码，diagnostic 承载阶段与副作用证据。
    const bool knownBusinessResult = IsKnownBusinessResult(reply.result());
    auto result = FromProto(reply.diagnostic(), knownBusinessResult ? static_cast<VirtrustRc>(reply.result())
                                                                 : VirtrustRc::ERROR);
    // UDS 回复也按生成规则过滤，避免控制字符进入 CLI 诊断。
    if (ValidMigrationAttemptId(reply.attempt_id())) {
        result.attemptId = reply.attempt_id();
    }
    if (ValidMigrationAttemptId(config.attemptId) && result.attemptId != config.attemptId) {
        // 业务回复必须与本次调用的身份一致；不可信回复按结果未知处理。
        return UnknownUdsFailure(MigrationErrorOrigin::Internal, config.attemptId);
    }
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
    return InvokePeerWithRetry(config_, timeout, "PrepareMigration", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.PrepareMigration(&context, request, reply);
                               });
}

// 2: 交换公钥
int32_t RpcClient::ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                       protos::EXchangePkAndReportReply *response)
{
    return InvokePeerWithRetry(config_, timeout, "ExchangePkAndReport", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.ExchangePkAndReport(&context, request, reply);
                               });
}

// 3: 开始迁移
int32_t RpcClient::StartMigration(uint32_t timeout, const protos::StartMigRequest &request,
                                  protos::StartMigReply *response)
{
    return InvokePeerWithRetry(config_, timeout, "StartMigration", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.StartMigration(&context, request, reply);
                               });
}

// 4：迁移虚机密码资源
int32_t RpcClient::SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                                    protos::VRsourceInfoReply *response)
{
    return InvokePeerWithRetry(config_, timeout, "SendVRsourceData", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.SendVRsourceData(&context, request, reply);
                               });
}

// 5: 通知迁移结果
int32_t RpcClient::NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                         protos::MigrateResultReply *response)
{
    return InvokePeerWithRetry(config_, timeout, "NotifyVRMigrateResult", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.NotifyVRMigrateResult(&context, request, reply);
                               });
}

int32_t RpcClient::QueryMigrationFinalResult(uint32_t timeout, const protos::QueryMigrationFinalResultRequest &request,
                                             protos::QueryMigrationFinalResultReply *response)
{
    // 查询复用阶段总期限和退避；IN_PROGRESS 转为空业务值，使包装层在期限内继续轮询。
    return InvokePeerWithRetry(config_, timeout, "QueryMigrationFinalResult", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.QueryMigrationFinalResult(&context, request, reply);
                               },
                               [](const protos::QueryMigrationFinalResultReply &reply) -> std::optional<int32_t> {
                                   if (reply.state() == protos::FINAL_RESULT_IN_PROGRESS) {
                                       return std::nullopt;
                                   }
                                   return 0;
                               });
}

int32_t RpcClient::QueryMigrationFinalResultOnce(uint32_t timeout,
                                                 const protos::QueryMigrationFinalResultRequest &request,
                                                 protos::QueryMigrationFinalResultReply *response)
{
    // 已取得 gRPC 成功回复时立即返回其原始状态；一般网络失败仍受同一总期限和重试次数约束。
    return InvokePeerWithRetry(config_, timeout, "QueryMigrationFinalResultOnce", response,
                               [&](auto &stub, auto &context, auto *reply) {
                                   return stub.QueryMigrationFinalResult(&context, request, reply);
                               },
                               [](const protos::QueryMigrationFinalResultReply &) -> std::optional<int32_t> {
                                   return 0;
                               });
}
}; // namespace virtrust
