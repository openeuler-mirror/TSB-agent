/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_service_impl.h"

#include <memory>
#include <exception>
#include <thread>
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
} // namespace

grpc::Status MigrationServiceImpl::PrepareMigration(grpc::ServerContext *context,
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
        session = mgr.CreateSession(MigrationSession::Role::Responder, request->uuid(), request->domainname(),
                                    request->desturi(), request->localuri(), request->flags(), std::move(admission));
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
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    auto session = SessionManager::GetInstance().GetSession(uuid);
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
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    auto session = SessionManager::GetInstance().GetSession(uuid);
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
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF||request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    auto session = SessionManager::GetInstance().GetSession(uuid);
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
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|NotifyVRMigrateResult request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    auto session = SessionManager::GetInstance().GetSession(uuid);
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
                                    request->desturi(), request->localuri(), request->flags());
        if (!session) {
            SetSourcePreflightFailure(response, VirtrustRc::ERROR, MigrationOperation::Validate,
                                      MigrationErrorOrigin::Internal);
            VIRTRUST_LOG_ERROR("|DomainMigrate|Session|Failed to create source session: uuid={}", request->uuid());
            return grpc::Status::OK;
        }
        sessionCreated = true;
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
