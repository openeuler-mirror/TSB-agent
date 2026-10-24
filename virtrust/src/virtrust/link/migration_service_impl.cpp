/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_service_impl.h"

#include <memory>
#include <optional>
#include <exception>
#include <chrono>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "libvirtrustd/defines.h"
#include "tsb_agent/tsb_agent.h"

#include "virtrust/api/domain.h"
#include "virtrust/base/logger.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_attempt_id.h"
#include "virtrust/link/migration_destination_uri.h"
#include "virtrust/link/migration_result.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
namespace {
// API 的查询只用于构造请求；守护进程取得独占资格后再次核验，避免等待 UDS 时虚机已变化。
bool CheckSourceDomain(const protos::DomainMigraterRequest &request, MigrationError &failure)
{
    failure = {MigrationStage::Preflight, MigrationSide::Source, MigrationOperation::Validate,
               MigrationErrorOrigin::Validation, false, 0};
    auto conn = std::make_unique<ConnCtx>();
    if (!conn->SetUri(request.localuri()) || !conn->Connect()) {
        failure = {MigrationStage::Preflight, MigrationSide::Source, MigrationOperation::ConnectLibvirt,
                   MigrationErrorOrigin::Libvirt, false, 0};
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Failed to connect to source URI: {}", request.localuri());
        return false;
    }
    std::unordered_map<std::string, DomainInfo> domains;
    if (DomainList(conn, LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE, domains, false, &failure) != VirtrustRc::OK) {
        failure.stage = MigrationStage::Preflight;
        failure.side = MigrationSide::Source;
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Failed to list source domains");
        return false;
    }
    failure = {MigrationStage::Preflight, MigrationSide::Source, MigrationOperation::Validate,
               MigrationErrorOrigin::Validation, false, 0};
    const auto it = domains.find(request.uuid());
    if (it == domains.end() || it->second.domainName != request.domainname() ||
        it->second.state != VIR_DOMAIN_SHUTOFF) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Source domain changed: name={}, uuid={}",
                           request.domainname(), request.uuid());
        return false;
    }
    return true;
}

// 源端会话尚未创建时没有可读取的会话诊断；这些拒绝均不会启动迁移副作用。
void SetSourcePreflightFailure(protos::DomainMigraterReply *response, VirtrustRc rc,
                               MigrationOperation operation, MigrationErrorOrigin origin,
                               bool hasRawCode = false, int32_t rawCode = 0) noexcept
{
    response->set_result(static_cast<uint32_t>(rc));
    try {
        MigrationResult diagnostic;
        diagnostic.rc = rc;
        diagnostic.outcome = MigrationOutcome::FailedBeforeEffect;
        diagnostic.manualCheckRequired = false;
        diagnostic.primaryError = {MigrationStage::Preflight, MigrationSide::Source, operation, origin,
                                   hasRawCode, rawCode};
        diagnostic.hasPrimaryError = true;
        ToProto(diagnostic, response->mutable_diagnostic());
    } catch (...) {
        // 诊断分配失败不能改写已经确定的 Busy 或业务错误码。
    }
}

// 异常可能发生在多个同步步骤之间；保留会话已有根因，没有证据时只给出保守阶段。
void SetSourceExceptionFailure(protos::DomainMigraterReply *response,
                               const std::shared_ptr<MigrationSession> &session, bool sessionCreated) noexcept
{
    response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    response->clear_diagnostic();
    try {
        MigrationResult diagnostic = session ? session->Diagnostic() : MigrationResult{};
        diagnostic.rc = VirtrustRc::ERROR;
        diagnostic.outcome = MigrationOutcome::Unknown;
        diagnostic.manualCheckRequired = true;
        if (!diagnostic.hasPrimaryError) {
            diagnostic.primaryError = {sessionCreated ? MigrationStage::Prepare : MigrationStage::Preflight,
                                       MigrationSide::Source, MigrationOperation::Validate,
                                       MigrationErrorOrigin::Internal, false, 0};
            diagnostic.hasPrimaryError = true;
        }
        ToProto(diagnostic, response->mutable_diagnostic());
    } catch (...) {
        response->clear_diagnostic();
    }
}

// Cleanup 异常时只撤销当前对象的登记，避免误删同 UUID 的替代会话。
void CleanupSourceSessionNoThrow(const std::shared_ptr<MigrationSession> &session) noexcept
{
    if (!session) {
        return;
    }
    try {
        session->Cleanup();
    } catch (...) {
        try {
            SessionManager::GetInstance().RemoveSessionIfCurrent(session->Id(), session.get());
        } catch (...) {
            // 异常边界不能再向 gRPC 框架抛出；极端残留需由人工排查。
        }
    }
}

// RPC 异常边界先撤销响应方会话，再返回协议错误；不能让异常带着节点资格逸出 gRPC。
void CleanupResponderSessionNoThrow(const std::shared_ptr<MigrationSession> &session) noexcept
{
    if (session == nullptr) {
        return;
    }
    try {
        session->Cleanup();
    } catch (...) {
        try {
            SessionManager::GetInstance().RemoveSessionIfCurrent(session->Id(), session.get());
        } catch (...) {
        }
    }
}

// 目的端会话若已失效或异常中断，就不能推断远端效果；保留已记录的更具体底层错误。
template <typename Reply>
void SetDestinationFailure(Reply *response, MigrationStage stage, MigrationOperation operation,
                           MigrationErrorOrigin origin, const std::shared_ptr<MigrationSession> &session = {}) noexcept
{
    // 业务失败码先于可能分配内存的诊断写入，避免异常留下 protobuf 缺省成功码。
    response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    try {
        MigrationResult diagnostic = session ? session->Diagnostic() : MigrationResult{};
        if (!diagnostic.hasPrimaryError) {
            diagnostic.primaryError = {stage, MigrationSide::Destination, operation, origin, false, 0};
            diagnostic.hasPrimaryError = true;
        }
        ToProto(diagnostic, response->mutable_diagnostic());
    } catch (...) {
        // 无法完整序列化时不留下半份诊断；调用方仍可依据非零业务码判定失败。
        response->clear_diagnostic();
    }
}

template <typename Action>
MigrateSessionRc RunResponderStep(const std::shared_ptr<MigrationSession> &session, const char *name, Action &&action)
{
    try {
        const auto result = std::forward<Action>(action)();
        if (result != MigrateSessionRc::OK) {
            CleanupResponderSessionNoThrow(session);
        }
        return result;
    } catch (const std::exception &error) {
        CleanupResponderSessionNoThrow(session);
        try {
            VIRTRUST_LOG_ERROR("|{}|END|returnF|Exception: {}", name, error.what());
        } catch (...) {
        }
    } catch (...) {
        CleanupResponderSessionNoThrow(session);
    }
    return MigrateSessionRc::ERROR;
}

// 入口先判重，再运行原有业务；完整请求与回复序列化后用于同阶段结果回放。
template <typename Request, typename Reply, typename Action>
grpc::Status RunCached(MigrationReplayCache &cache, MigrationReplayCache::Step step,
                       const Request *request, Reply *response, Action &&action)
{
    if (request == nullptr || response == nullptr) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Migration request or reply is null"};
    }
    if (!ValidMigrationAttemptId(request->attempt_id())) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Migration attempt ID is missing or invalid"};
    }
    MigrationReplayCache::Admission admission;
    try {
        // 比较完整请求字节而非仅比较 UUID：同一尝试同一阶段若更换密文、证书等负载必须拒绝。
        // 这里只做缓存键比对，不替代 gRPC 在网络上的 protobuf 编解码。
        std::string requestBytes;
        if (!request->SerializeToString(&requestBytes)) {
            return {grpc::StatusCode::INTERNAL, "Failed to serialize migration request"};
        }
        admission = cache.Begin(request->attempt_id(), step, requestBytes,
                                MigrationReplayCache::Clock::now(), request->uuid());
        // 判重发生在业务动作前：只有 Execute 才能落入下方 action，其他结论直接返回。
        switch (admission.decision) {
            case MigrationReplayCache::Decision::Replay:
                // 旧成功回复不能越过同 UUID 已登记的新尝试；无会话时允许重放收尾回复。
                if (const auto current = SessionManager::GetInstance().GetSession(request->uuid());
                    current != nullptr && current->AttemptId() != request->attempt_id()) {
                    return {grpc::StatusCode::FAILED_PRECONDITION,
                            "Migration attempt does not match current session"};
                }
                if (!response->ParseFromString(admission.reply)) {
                    return {grpc::StatusCode::INTERNAL, "Failed to restore migration reply"};
                }
                return grpc::Status::OK;
            case MigrationReplayCache::Decision::InProgress:
                // 首个处理尚未完成，不能猜测其结果，也不能并发再次进入有副作用的业务。
                // 专用 details 与普通网络 UNAVAILABLE 区分：源端只在阶段期限内查询缓存完成结果。
                return {grpc::StatusCode::UNAVAILABLE, "Migration step is already in progress",
                        MIGRATION_STEP_IN_PROGRESS_DETAIL};
            case MigrationReplayCache::Decision::Conflict:
                // 尝试身份和阶段相同但负载不同，不把它当作合法重试。
                return {grpc::StatusCode::FAILED_PRECONDITION, "Migration step payload conflicts with prior request"};
            case MigrationReplayCache::Decision::Capacity:
                return {grpc::StatusCode::RESOURCE_EXHAUSTED, "Migration replay cache is full"};
            case MigrationReplayCache::Decision::Unavailable:
                return {grpc::StatusCode::ABORTED, "Migration step result is unavailable for replay"};
            case MigrationReplayCache::Decision::Execute:
                break;
        }
        const auto status = std::forward<Action>(action)();
        // 会话可能已在业务动作中清理；保存完整回复才能在会话消失后重放最终确认或错误诊断。
        std::string replyBytes;
        if (!response->SerializeToString(&replyBytes)) {
            cache.CompleteUnreplayable(admission);
            return {grpc::StatusCode::INTERNAL, "Failed to serialize migration reply"};
        }
        // ACK 为零只证明通知已处理；源端上报失败时不能把迁移本身标成成功。
        // gRPC 失败时即使 protobuf 默认 result 为零，也不能记录为目的端完成成功。
        std::optional<bool> finalSuccess;
        if constexpr (std::is_same_v<Request, protos::MigrateResultRequest>) {
            if (step == MigrationReplayCache::Step::Finish && status.ok()) {
                finalSuccess = request->result() == 0 && response->result() == 0;
            }
        }
        if (!cache.Complete(admission, replyBytes, MigrationReplayCache::Clock::now(), finalSuccess)) {
            // 副作用可能已完成；保留墓碑并返回真实首发结果，重复请求将收到不可回放错误。
            try {
                VIRTRUST_LOG_ERROR("Migration replay result could not be retained: attempt={}, step={}",
                                   request->attempt_id(), static_cast<int>(step));
            } catch (...) {
            }
        }
        return status;
    } catch (...) {
        // 已进入业务后出现异常，保留不可回放墓碑；绝不因缓存失败重新执行业务。
        if (admission.decision == MigrationReplayCache::Decision::Execute) {
            cache.CompleteUnreplayable(admission);
        }
        return {grpc::StatusCode::INTERNAL, "Migration replay boundary failed"};
    }
}

template <typename Reply>
bool MatchResponderAttempt(const std::shared_ptr<MigrationSession> &session, const std::string &attemptId,
                           Reply *response, MigrationStage stage)
{
    // 无会话仍交由旧路径给出明确的缺失诊断；只有活跃会话才比较尝试身份。
    if (session == nullptr || session->AttemptId() == attemptId) {
        return true;
    }
    SetDestinationFailure(response, stage, MigrationOperation::CheckIdentity,
                          MigrationErrorOrigin::Validation);
    return false;
}
} // namespace

MigrationServiceImpl::MigrationServiceImpl()
    // 服务实例覆盖 gRPC Server 生命周期，缓存跨请求存在；活跃会话的旧阶段不按 TTL 淘汰。
    // 探针只按 attempt ID 查询已登记会话，防止长会话使早期阶段的回放记录提前过期。
    : replayCache_(256, 16 * 1024 * 1024, std::chrono::minutes(10),
                   [](const std::string &attemptId) {
                       return SessionManager::GetInstance().HasAttempt(attemptId);
                   })
{}

grpc::Status MigrationServiceImpl::PrepareMigration(grpc::ServerContext *context,
                                                    const protos::PrepareMigRequest *request,
                                                    protos::PrepareMigReply *response)
{
    return RunCached(replayCache_, MigrationReplayCache::Step::Prepare, request, response,
                     [&] { return PrepareMigrationUncached(context, request, response); });
}

grpc::Status MigrationServiceImpl::PrepareMigrationUncached(grpc::ServerContext *context,
                                                            const protos::PrepareMigRequest *request,
                                                            protos::PrepareMigReply *response)
{
    if (request == nullptr || response == nullptr) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Migration preparation request or reply is null");
    }
    // 预设业务结果为 Error，避免后续异常被误报为成功
    response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    std::shared_ptr<MigrationSession> session;
    try {
        VIRTRUST_LOG_DEBUG("|PrepareMigration|START||start handle rpc request");
        // 先取得目的节点资格；会话尚未发布时发生竞争，不会留下半初始化的会话。
        NodeAdmission admission;
        const auto outcome = admission.TryAcquire(AdmissionKind::Migration);
        if (outcome != LockOutcome::Acquired) {
            const auto resultCode = outcome == LockOutcome::Busy ? VirtrustRc::BUSY : VirtrustRc::ERROR;
            response->set_result(static_cast<uint32_t>(resultCode));
            // 准入尚未成功，目的端业务没有开始；保留权限错误与 Busy 的区别。
            MigrationResult diagnostic;
            diagnostic.rc = resultCode;
            diagnostic.outcome = MigrationOutcome::FailedBeforeEffect;
            diagnostic.manualCheckRequired = false;
            diagnostic.primaryError = {MigrationStage::Prepare, MigrationSide::Destination,
                                       MigrationOperation::AcquireAdmission, MigrationErrorOrigin::Validation,
                                       outcome == LockOutcome::Error, admission.LastErrno()};
            diagnostic.hasPrimaryError = true;
            ToProto(diagnostic, response->mutable_diagnostic());
            try {
                VIRTRUST_LOG_ERROR("|PrepareMigration|Admission|{}", admission.LastError());
            } catch (...) {
            }
            return grpc::Status::OK;
        }

        auto &mgr = SessionManager::GetInstance();
        // Prepare 是目的端会话身份的唯一建档点；后续 RPC 只读取并校验，不能覆盖该身份。
        session = mgr.CreateSession(MigrationSession::Role::Responder, request->uuid(), request->domainname(),
                                    request->desturi(), request->localuri(), request->flags(), std::move(admission),
                                    request->attempt_id());
        if (session == nullptr) {
            VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|domain name: {}|Session already exists",
                               request->domainname());
            SetDestinationFailure(response, MigrationStage::Prepare, MigrationOperation::Validate,
                                  MigrationErrorOrigin::Internal);
            return grpc::Status::OK;
        }
        if (session->OnMigrateRequestReceived() != MigrateSessionRc::OK) {
            // 预检查失败是终态；不能让无定时器的 Failed 会话永久持有节点资格。
            MigrationResult diagnostic = session->Diagnostic();
            if (!diagnostic.hasPrimaryError) {
                diagnostic.outcome = MigrationOutcome::FailedBeforeEffect;
                diagnostic.manualCheckRequired = false;
                diagnostic.primaryError = {MigrationStage::Prepare, MigrationSide::Destination,
                                           MigrationOperation::Validate, MigrationErrorOrigin::Validation, false, 0};
                diagnostic.hasPrimaryError = true;
            }
            ToProto(diagnostic, response->mutable_diagnostic());
            session->Cleanup();
            return grpc::Status::OK;
        }
        response->set_result(static_cast<uint32_t>(VirtrustRc::OK));
        return grpc::Status::OK;
    } catch (const std::exception &error) {
        CleanupResponderSessionNoThrow(session);
        try {
            SetDestinationFailure(response, MigrationStage::Prepare, MigrationOperation::Validate,
                                  MigrationErrorOrigin::Internal, session);
        } catch (...) {
        }
        try {
            VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|Exception: {}", error.what());
        } catch (...) {
        }
        return grpc::Status::OK;
    } catch (...) {
        CleanupResponderSessionNoThrow(session);
        try {
            SetDestinationFailure(response, MigrationStage::Prepare, MigrationOperation::Validate,
                                  MigrationErrorOrigin::Internal, session);
        } catch (...) {
        }
        return grpc::Status::OK;
    }
}

// 2: 交换公钥和报告
grpc::Status MigrationServiceImpl::ExchangePkAndReport(grpc::ServerContext *context,
                                                       const protos::EXchangePkAndReportRequest *request,
                                                       protos::EXchangePkAndReportReply *response)
{
    return RunCached(replayCache_, MigrationReplayCache::Step::Exchange, request, response,
                     [&] { return ExchangePkAndReportUncached(context, request, response); });
}

grpc::Status MigrationServiceImpl::ExchangePkAndReportUncached(grpc::ServerContext *context,
                                                               const protos::EXchangePkAndReportRequest *request,
                                                               protos::EXchangePkAndReportReply *response)
{
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    auto session = SessionManager::GetInstance().GetSession(uuid);
    if (!MatchResponderAttempt(session, request->attempt_id(), response, MigrationStage::KeyExchange)) {
        return grpc::Status::OK;
    }
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|ExchangePkAndReport|END|returnF|domain name: {}|Can't find session.", domainName);
        SetDestinationFailure(response, MigrationStage::KeyExchange, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal);
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = RunResponderStep(session, "ExchangePkAndReport", [&] {
        VIRTRUST_LOG_DEBUG("|ExchangePkAndReport|START||start handle rpc request");
        return session->OnExchangeKeyRequestReceived(request, response);
    });
    if (rc != MigrateSessionRc::OK) {
        SetDestinationFailure(response, MigrationStage::KeyExchange, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal, session);
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    return grpc::Status::OK;
}

// 3: 开始迁移通知
grpc::Status MigrationServiceImpl::StartMigration(grpc::ServerContext *context, const protos::StartMigRequest *request,
                                                  protos::StartMigReply *response)
{
    return RunCached(replayCache_, MigrationReplayCache::Step::Start, request, response,
                     [&] { return StartMigrationUncached(context, request, response); });
}

grpc::Status MigrationServiceImpl::StartMigrationUncached(grpc::ServerContext *context,
                                                          const protos::StartMigRequest *request,
                                                          protos::StartMigReply *response)
{
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    auto session = SessionManager::GetInstance().GetSession(uuid);
    if (!MatchResponderAttempt(session, request->attempt_id(), response, MigrationStage::Start)) {
        return grpc::Status::OK;
    }
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|domain name: {}|Can't find session.", domainName);
        SetDestinationFailure(response, MigrationStage::Start, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal);
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = RunResponderStep(session, "StartMigration", [&] {
        VIRTRUST_LOG_DEBUG("|StartMigration|START||start handle rpc request");
        return session->OnStartMigrationRequestReceived();
    });
    if (rc != MigrateSessionRc::OK) {
        SetDestinationFailure(response, MigrationStage::Start, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal, session);
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    return grpc::Status::OK;
}

// 4：迁移虚机密码资源
grpc::Status MigrationServiceImpl::SendVRsourceData(grpc::ServerContext *context,
                                                    const protos::VRsourceInfoRequest *request,
                                                    protos::VRsourceInfoReply *response)
{
    return RunCached(replayCache_, MigrationReplayCache::Step::Transfer, request, response,
                     [&] { return SendVRsourceDataUncached(context, request, response); });
}

grpc::Status MigrationServiceImpl::SendVRsourceDataUncached(grpc::ServerContext *context,
                                                            const protos::VRsourceInfoRequest *request,
                                                            protos::VRsourceInfoReply *response)
{
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF||request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    auto session = SessionManager::GetInstance().GetSession(uuid);
    if (!MatchResponderAttempt(session, request->attempt_id(), response, MigrationStage::DataTransfer)) {
        return grpc::Status::OK;
    }
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF|uuid: {}|Can't find session.", uuid);
        SetDestinationFailure(response, MigrationStage::DataTransfer, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal);
        response->set_result(1);
        return grpc::Status::OK;
    }
    // 业务 result 只表示成败，TSB 原始码由 diagnostic 单独携带。
    MigrateSessionRc rc = RunResponderStep(session, "SendVRsourceData", [&] {
        VIRTRUST_LOG_DEBUG("|SendVRsourceData|START||start handle rpc request");
        return session->OnTransferDataRequestReceived(request);
    });
    if (rc != MigrateSessionRc::OK) {
        SetDestinationFailure(response, MigrationStage::DataTransfer, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal, session);
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    return grpc::Status::OK;
}

// 5: 通知迁移结果
grpc::Status MigrationServiceImpl::NotifyVRMigrateResult(grpc::ServerContext *context,
                                                         const protos::MigrateResultRequest *request,
                                                         protos::MigrateResultReply *response)
{
    return RunCached(replayCache_, MigrationReplayCache::Step::Finish, request, response,
                     [&] { return NotifyVRMigrateResultUncached(context, request, response); });
}

grpc::Status MigrationServiceImpl::QueryMigrationFinalResult(
    grpc::ServerContext *, const protos::QueryMigrationFinalResultRequest *request,
    protos::QueryMigrationFinalResultReply *response)
{
    if (request == nullptr || response == nullptr || request->uuid().empty() ||
        !ValidMigrationAttemptId(request->attempt_id())) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Invalid migration final-result query"};
    }
    try {
        // 同 UUID 已登记另一轮会话时，旧缓存事实不能被当作当前尝试的最终确认。
        const auto current = SessionManager::GetInstance().GetSession(request->uuid());
        if (current != nullptr && current->AttemptId() != request->attempt_id()) {
            response->set_state(protos::FINAL_RESULT_UNKNOWN);
            return grpc::Status::OK;
        }
        const auto snapshot = replayCache_.QueryFinal(request->uuid(), request->attempt_id());
        // 查询只读取内存快照，不调用可信组件，也不推进目的端会话状态。
        switch (snapshot.state) {
            case MigrationReplayCache::FinalState::InProgress:
                response->set_state(protos::FINAL_RESULT_IN_PROGRESS);
                break;
            case MigrationReplayCache::FinalState::CompletedSuccess:
                response->set_state(protos::FINAL_RESULT_COMPLETED_SUCCESS);
                break;
            case MigrationReplayCache::FinalState::CompletedFailure: {
                protos::MigrateResultReply recorded;
                if (!recorded.ParseFromString(snapshot.reply)) {
                    return {grpc::StatusCode::INTERNAL, "Failed to decode recorded migration result"};
                }
                response->set_state(protos::FINAL_RESULT_COMPLETED_FAILURE);
                if (recorded.has_diagnostic()) {
                    *response->mutable_diagnostic() = recorded.diagnostic();
                }
                break;
            }
            case MigrationReplayCache::FinalState::Unknown:
                response->set_state(protos::FINAL_RESULT_UNKNOWN);
                break;
        }
        return grpc::Status::OK;
    } catch (...) {
        return {grpc::StatusCode::INTERNAL, "Migration final-result query failed"};
    }
}

grpc::Status MigrationServiceImpl::DomainQueryMigrationFinalResult(
    grpc::ServerContext *, const protos::QueryMigrationFinalResultRequest *request,
    protos::QueryMigrationFinalResultReply *response)
{
    if (request == nullptr || response == nullptr || request->uuid().empty() ||
        !ValidMigrationAttemptId(request->attempt_id())) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Invalid local migration result query"};
    }
    std::string destIp;
    if (!ParseMigrationDestinationUri(request->dest_uri(), destIp)) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Invalid migration destination URI"};
    }
    try {
        // 手工查询不取得迁移独占资格，也不要求原会话存在；节点间身份仍由现有 TLS 配置约束。
        LinkConfig config = ConfigMgr::Instance().GetLinkConfig();
        config.ip = destIp;
        RpcClient client(config);
        protos::QueryMigrationFinalResultRequest peerRequest;
        peerRequest.set_uuid(request->uuid());
        peerRequest.set_attempt_id(request->attempt_id());
        // 人工查询需要观察目的端当下的 IN_PROGRESS，不等待它变成终态。
        if (client.QueryMigrationFinalResultOnce(5, peerRequest, response) == RPC_TRANSPORT_FAILURE) {
            return {grpc::StatusCode::UNAVAILABLE, "Destination final-result query failed"};
        }
        return grpc::Status::OK;
    } catch (...) {
        return {grpc::StatusCode::INTERNAL, "Local migration result query failed"};
    }
}

grpc::Status MigrationServiceImpl::NotifyVRMigrateResultUncached(grpc::ServerContext *context,
                                                                 const protos::MigrateResultRequest *request,
                                                                 protos::MigrateResultReply *response)
{
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|NotifyVRMigrateResult request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    auto session = SessionManager::GetInstance().GetSession(uuid);
    if (!MatchResponderAttempt(session, request->attempt_id(), response, MigrationStage::DestinationCommit)) {
        return grpc::Status::OK;
    }
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|NotifyVRMigrateResult uuid: {}|Can't find session.", uuid);
        SetDestinationFailure(response, MigrationStage::DestinationCommit, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal);
        response->set_result(1);
        return grpc::Status::OK;
    }
    MigrateSessionRc rc = RunResponderStep(session, "NotifyVRMigrateResult", [&] {
        VIRTRUST_LOG_DEBUG("|NotifyVRMigrateResult|START||start handle rpc request");
        return session->OnFinishedRequestReceived(request->result() == 0);
    });
    if (rc != MigrateSessionRc::OK) {
        SetDestinationFailure(response, MigrationStage::DestinationCommit, MigrationOperation::Validate,
                              MigrationErrorOrigin::Internal, session);
        response->set_result(1);
        return grpc::Status::OK;
    }
    response->set_result(0);
    return grpc::Status::OK;
}

// 本机 UDS 入口：独占资格覆盖源端同步会话和清理；有效请求的业务失败写入 reply 并返回 gRPC OK。
grpc::Status MigrationServiceImpl::DomainMigrate(grpc::ServerContext *context,
                                                 const protos::DomainMigraterRequest *request,
                                                 protos::DomainMigraterReply *response)
{
    if (request == nullptr || response == nullptr) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Migration request or reply is null");
    }
    response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
    // 置于异常处理之外，确保异常路径清理会话时仍持有本节点独占资格。
    NodeAdmission admission;
    std::shared_ptr<MigrationSession> session;
    bool sessionCreated = false;
    try {
        // 有效的调用方身份先于预检查回填；Busy/验证失败也必须能被 UDS 客户端匹配。
        if (ValidMigrationAttemptId(request->attempt_id())) {
            response->set_attempt_id(request->attempt_id());
        }
        VIRTRUST_LOG_DEBUG("|DomainMigrate|START||start handle uds request");
        // 独立校验 UDS 输入，防止调用方绕过 API 让本节点锁保护远端 libvirt 操作。
        if (!IsLocalMigrationSourceUri(request->localuri())) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Validation);
            VIRTRUST_LOG_ERROR("|DomainMigrate|SourceUri|Unsupported migration source URI: {}", request->localuri());
            return grpc::Status::OK;
        }
        std::string destIp;
        if (!ParseMigrationDestinationUri(request->desturi(), destIp)) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Validation);
            // 非法 URI 可能包含凭据或查询文本，日志仅记录拒绝原因，不回显原文。
            VIRTRUST_LOG_ERROR("|MigrationServiceImpl DomainMigrate|DestinationUri|Invalid destination URI");
            return grpc::Status::OK;
        }
        // 本机 UDS 入口独立约束标志，不能依赖调用方先经过 API 校验。
        constexpr unsigned int supportedFlags = VIR_MIGRATE_OFFLINE | VIR_MIGRATE_PERSIST_DEST | MIGRATE_UNDEFINE_SOURCE;
        if (request->flags() != supportedFlags) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Validation);
            // 日志异常不能把已确定的预检查拒绝改写为未知业务结果。
            try {
                VIRTRUST_LOG_ERROR("|DomainMigrate|Flags|Unsupported migration flags: {}", request->flags());
            } catch (...) {
            }
            return grpc::Status::OK;
        }
        if (!request->attempt_id().empty() && !ValidMigrationAttemptId(request->attempt_id())) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Validation);
            return grpc::Status::OK;
        }

        // 令牌由当前守护进程请求持有，直至源端状态机和 Cleanup 全部返回；不从 API 转移描述符。
        const auto outcome = admission.TryAcquire(AdmissionKind::Migration);
        if (outcome != LockOutcome::Acquired) {
            SetSourcePreflightFailure(response, outcome == LockOutcome::Busy ? VirtrustRc::BUSY : VirtrustRc::ERROR,
                                      MigrationOperation::AcquireAdmission, MigrationErrorOrigin::Validation,
                                      outcome == LockOutcome::Error, admission.LastErrno());
            // 诊断失败不能把已经确定的 Busy 改写为通用 Error。
            try {
                VIRTRUST_LOG_ERROR("|DomainMigrate|Admission|{}", admission.LastError());
            } catch (...) {
            }
            return grpc::Status::OK;
        }
        MigrationError sourceFailure;
        if (!CheckSourceDomain(*request, sourceFailure)) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, sourceFailure.operation,
                                      sourceFailure.origin, sourceFailure.hasRawCode, sourceFailure.rawCode);
            return grpc::Status::OK;
        }

        LinkConfig config = ConfigMgr::Instance().GetLinkConfig();
        config.ip = destIp;
        auto &mgr = SessionManager::GetInstance();
        // 源端整个迁移过程始终由外层请求持锁admission；session 无须再获取同一节点的锁
        session = mgr.CreateSession(MigrationSession::Role::Initiator, request->uuid(), request->domainname(),
                                    request->desturi(), request->localuri(), request->flags(), {},
                                    request->attempt_id());
        if (!session) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Internal);
            VIRTRUST_LOG_ERROR("|DomainMigrate|Session|Failed to create source session: uuid={}", request->uuid());
            return grpc::Status::OK;
        }
        sessionCreated = true;
        // 直接调用 UDS 且未提供 attempt ID 时，源端会话会把这个实际用于会话的 ID写回回复。
        response->set_attempt_id(session->AttemptId());
        // 源端会话同步运行；先清理会话，再由 admission 析构释放独占资格。
        session->SetRpcClient(std::make_unique<RpcClient>(config));
        // Start 同步串联跨节点准备、密钥交换、libvirt/可信资源传输及两端收尾。
        const auto result = session->Start();
        // Cleanup 可能移除 manager 的最后一个共享引用；先保存业务结果，再释放会话资格。
        const auto diagnostic = session->Diagnostic();
        session->Cleanup();
        session.reset();
        ToProto(diagnostic, response->mutable_diagnostic());
        if (result != MigrateSessionRc::OK) {
            response->set_result(static_cast<uint32_t>(diagnostic.rc));
            VIRTRUST_LOG_ERROR("|MigrationServiceImpl DomainMigrate|END|returnF|domain : {} migrate failed.",
                               request->domainname());
            return grpc::Status::OK;
        }
        response->set_result(static_cast<uint32_t>(VirtrustRc::OK));
        try {
            VIRTRUST_LOG_DEBUG("|DomainMigrate|END|returnS|");
        } catch (...) {
            // 成功后的诊断失败不改变已经完成的迁移结果。
        }
    } catch (const std::exception &error) {
        // 异常也须移除已创建的会话；独占资格随栈展开自动释放。
        CleanupSourceSessionNoThrow(session);
        SetSourceExceptionFailure(response, session, sessionCreated);
        try {
            VIRTRUST_LOG_ERROR("|DomainMigrate|Exception|{}", error.what());
        } catch (...) {
        }
    } catch (...) {
        CleanupSourceSessionNoThrow(session);
        SetSourceExceptionFailure(response, session, sessionCreated);
        try {
            VIRTRUST_LOG_ERROR("|DomainMigrate|Exception|Unknown source migration failure");
        } catch (...) {
        }
    }
    return grpc::Status::OK;
}

} // namespace virtrust
