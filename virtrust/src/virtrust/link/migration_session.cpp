/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_session.h"

#include <iostream>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <utility>

#include "virtrust/api/define_private.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/migration_attempt_id.h"
#include "virtrust/link/proto/proto_tools.h"

#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {

namespace {
// RPC timeout unit: seconds
constexpr uint32_t RPC_SIGNAL_TIMEOUT = 5;
constexpr uint32_t RPC_TRANSFER_TIMEOUT = 20;

unsigned int GetFlagCleard(const unsigned int &flags, const unsigned int &clear)
{
    return flags & ~clear;
}
} // namespace

std::shared_ptr<MigrationSession> SessionManager::CreateSession(MigrationSession::Role role, const std::string &uuid,
                                                                const std::string &domainName,
                                                                const std::string &destUri,
                                                                const std::string &localUri,
                                                                const unsigned int flags,
                                                                NodeAdmission admission, std::string attemptId)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = sessions_.find(uuid);
    if (it != sessions_.end()) {
        VIRTRUST_LOG_ERROR("|CreateSession|END|returnF|uuid: {}|already exists session with same uuid.", uuid);
        return nullptr;
    }

    // 先把令牌交给对象，再发布到 manager；其他 RPC 不会看到尚未持锁的响应方会话。
    auto session = std::make_shared<MigrationSession>(role, uuid, domainName, destUri, localUri, flags,
                                                      std::move(admission), std::move(attemptId));
    sessions_[uuid] = session;
    return session;
}

std::shared_ptr<MigrationSession> SessionManager::GetSession(const std::string &uuid)
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(uuid);
    if (it == sessions_.end()) {
        return nullptr;
    }
    return it->second;
}

bool SessionManager::HasAttempt(const std::string &attemptId)
{
    // 缓存淘汰时只读取已发布会话；这里不反向访问缓存，保持锁获取顺序单向。
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto &entry : sessions_) {
        if (entry.second->AttemptId() == attemptId) {
            return true;
        }
    }
    return false;
}

void SessionManager::RemoveSession(const std::string &uuid)
{
    std::lock_guard<std::mutex> lock(mtx_);
    sessions_.erase(uuid);
}

void SessionManager::RemoveSessionIfCurrent(const std::string &uuid, const MigrationSession *expected)
{
    std::lock_guard<std::mutex> lock(mtx_);
    const auto it = sessions_.find(uuid);
    if (it != sessions_.end() && it->second.get() == expected) {
        sessions_.erase(it);
    }
}

MigrationSession::MigrationSession(Role role, const std::string &uuid, const std::string &domainName,
                                   const std::string &destUri, const std::string &localUri, const unsigned int flags,
                                   NodeAdmission admission, std::string attemptId)
    // 源端创建一次会话只生成一次身份；目的端必须沿用 Prepare 请求传来的身份。
    : role_(role),
      state_(State::Init),
      uuid_(uuid),
      attemptId_(role == Role::Initiator && attemptId.empty() ? GenerateMigrationAttemptId() : std::move(attemptId)),
      domainName_(domainName),
      destUri_(destUri),
      localUri_(localUri),
      flags_(flags),
      admission_(std::move(admission))
{}

// 服务入口在清理会话前复制快照；读取与阶段更新共用会话锁。
MigrationResult MigrationSession::Diagnostic() const
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    return result_;
}

void MigrationSession::RecordFailure(MigrationStage stage, MigrationSide side, MigrationOperation operation,
                                     MigrationErrorOrigin origin, bool hasRawCode, int32_t rawCode,
                                     MigrationOutcome outcome)
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    // 第一处业务错误是根因，后续补偿失败不得覆盖它。
    if (result_.hasPrimaryError) {
        return;
    }
    result_.rc = VirtrustRc::ERROR;
    result_.outcome = outcome;
    result_.primaryError = {stage, side, operation, origin, hasRawCode, rawCode};
    result_.hasPrimaryError = true;
    result_.manualCheckRequired = outcome == MigrationOutcome::Unknown || outcome == MigrationOutcome::Partial;
}

void MigrationSession::RecordPeerFailure(const protos::MigrationDiagnostic &diagnostic, VirtrustRc rc,
                                         MigrationStage fallbackStage, MigrationOperation fallbackOperation)
{
    const auto peer = FromProto(diagnostic, rc);
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (result_.hasPrimaryError) {
        return;
    }
    // 业务回复中的诊断可能来自较旧的异常分支；缺少根因时使用当前 RPC 阶段作为保守兜底。
    result_.primaryError = peer.hasPrimaryError
        ? peer.primaryError
        : MigrationError{fallbackStage, MigrationSide::Destination, fallbackOperation,
                         MigrationErrorOrigin::Internal, false, 0};
    result_.hasPrimaryError = true;
    result_.rc = rc;
    result_.outcome = peer.hasPrimaryError && peer.outcome != MigrationOutcome::Success
        ? peer.outcome : MigrationOutcome::Unknown;
    result_.manualCheckRequired = result_.outcome == MigrationOutcome::Unknown ||
                                  result_.outcome == MigrationOutcome::Partial;
}

void MigrationSession::ConfirmStep(MigrationStep step)
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    // 位集只记录已收到成功返回的里程碑，不推断远端未回复时的实际状态。
    result_.confirmedSteps |= static_cast<uint32_t>(step);
}

void MigrationSession::MarkSuccess()
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (result_.hasPrimaryError) {
        return;
    }
    result_.rc = VirtrustRc::OK;
    result_.outcome = MigrationOutcome::Success;
    result_.manualCheckRequired = false;
}

void MigrationSession::AddCompensationError(MigrationStage stage, MigrationSide side, MigrationOperation operation,
                                            MigrationErrorOrigin origin, bool hasRawCode, int32_t rawCode) noexcept
{
    try {
        std::lock_guard<std::recursive_mutex> guard(operationMutex_);
        // 补偿异常只能追加，不能覆盖第一处业务错误；记录内存不足也不能中断后续补偿。
        result_.compensationErrors.push_back({stage, side, operation, origin, hasRawCode, rawCode});
        result_.manualCheckRequired = true;
    } catch (...) {
    }
}

// 源端阶段由同步调用逐步推进；阶段定时器只观察超时，不代替底层调用给出最终结果。
MigrateSessionRc MigrationSession::Start()
{
    VIRTRUST_LOG_DEBUG("|Start|START|");
    if (role_ != Role::Initiator) {
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Init);
    return SendMigrateRequest();
}

// 第一条节点间消息先确认目的端接纳；只有有效成功回复才允许记录接纳状态。
MigrateSessionRc MigrationSession::SendMigrateRequest()
{
    VIRTRUST_LOG_DEBUG("|SendMigrateRequest|START|");
    if (!rpcClient_) {
        RecordFailure(MigrationStage::Prepare, MigrationSide::Source, MigrationOperation::Validate,
                      MigrationErrorOrigin::Internal, false, 0, MigrationOutcome::FailedBeforeEffect);
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}|rpc client is nullptr.", domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::PrepareMigRequest req;
    // 后续阶段都复用会话身份，不能按 RPC 重新生成，否则目的端会视为其他尝试。
    req.set_uuid(uuid_);
    req.set_attempt_id(attemptId_);
    req.set_domainname(domainName_);

    protos::PrepareMigReply reply;

    int32_t rc = rpcClient_->PrepareMigration(RPC_SIGNAL_TIMEOUT, req, &reply);
    if (rc == RPC_TRANSPORT_FAILURE) {
        // 网络失败时 reply 仍可能保持 protobuf 默认零值，不能读取它或宣称目的端已准备。
        RecordFailure(MigrationStage::Prepare, MigrationSide::Source, MigrationOperation::NotifyPeer,
                      MigrationErrorOrigin::Grpc);
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}|Prepare RPC did not return a reply.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    bool ok = (rc == 0 && reply.result() == 0);

    if (!ok) {
        RecordPeerFailure(reply.diagnostic(), static_cast<VirtrustRc>(reply.result()), MigrationStage::Prepare,
                          MigrationOperation::Validate);
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}"
                           "|PrepareMigration failed: rpc={}, business={}", domainName_, rc, reply.result());
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    {
        std::lock_guard<std::recursive_mutex> guard(operationMutex_);
        destinationAccepted_ = true;
    }
    return OnMigrateResponseReceived();
}

MigrateSessionRc MigrationSession::OnMigrateResponseReceived()
{
    VIRTRUST_LOG_DEBUG("|OnMigrateResponseReceived|START|");
    EnterState(State::WaitingKey);
    return SendExchangeKey();
}

MigrateSessionRc MigrationSession::SendExchangeKey()
{
    VIRTRUST_LOG_DEBUG("|SendExchangeKey|START|");
    protos::EXchangePkAndReportRequest req;
    MigrateSessionRc rc = GetExchangePkAndReport(&req, nullptr);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|domain name: {}|Get local cert and report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::EXchangePkAndReportReply res;
    int32_t ret = rpcClient_->ExchangePkAndReport(RPC_TRANSFER_TIMEOUT, req, &res);
    if (ret != 0 || res.result() != 0) {
        if (ret == RPC_TRANSPORT_FAILURE) {
            // 未收到有效回复时，protobuf 的默认零值不能代表目的端成功。
            RecordFailure(MigrationStage::KeyExchange, MigrationSide::Source, MigrationOperation::NotifyPeer,
                          MigrationErrorOrigin::Grpc);
        } else {
            const auto businessRc = res.result() != 0 ? static_cast<VirtrustRc>(res.result()) : VirtrustRc::ERROR;
            RecordPeerFailure(res.diagnostic(), businessRc, MigrationStage::KeyExchange,
                              MigrationOperation::ExchangeKey);
        }
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|domain name: {}|Exchange cert and report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    return OnExchangeKeyResponseReceived(res);
}

MigrateSessionRc MigrationSession::OnExchangeKeyResponseReceived(protos::EXchangePkAndReportReply &res)
{
    // 校验证书和报告
    VIRTRUST_LOG_DEBUG("|OnExchangeKeyResponseReceived|START|");
    EnterState(State::CertVerify);

    // 回复身份必须与本次会话一致；不能把对端提供的任意 UUID 直接交给可信组件校验。
    if (res.uuid() != uuid_) {
        RecordFailure(MigrationStage::KeyExchange, MigrationSide::Source, MigrationOperation::CheckIdentity,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|Identity|Peer reply UUID does not match session: {}",
                           uuid_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 1. 校验对端证书
    MigrateSessionRc rc = VerifyCertificate(res.uuid(), res.cert(), res.publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Verify peer cert failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 2.校验对端报告
    rc = VerifyHostAndVmReport(res.hostreport(), res.vmreport(), false);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 3.导入tcm2 key
    rc = ImportTcm2Key(res.tcm2key());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Import tcm2 key failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return SendStartMigration();
}

MigrateSessionRc MigrationSession::SendStartMigration()
{
    VIRTRUST_LOG_DEBUG("|SendStartMigration|START|");
    protos::StartMigRequest req;
    req.set_domainname(domainName_);
    req.set_uuid(uuid_);
    req.set_attempt_id(attemptId_);

    protos::StartMigReply res;
    int32_t ret = rpcClient_->StartMigration(RPC_SIGNAL_TIMEOUT, req, &res);
    if (ret != 0) {
        if (ret == RPC_TRANSPORT_FAILURE) {
            RecordFailure(MigrationStage::Start, MigrationSide::Source, MigrationOperation::NotifyPeer,
                          MigrationErrorOrigin::Grpc);
        } else {
            const auto businessRc = res.result() != 0 ? static_cast<VirtrustRc>(res.result()) : VirtrustRc::ERROR;
            RecordPeerFailure(res.diagnostic(), businessRc, MigrationStage::Start, MigrationOperation::Validate);
        }
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|domain name: {}|Send start migration signal failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    if (res.result() != 0) {
        RecordPeerFailure(res.diagnostic(), static_cast<VirtrustRc>(res.result()), MigrationStage::Start,
                          MigrationOperation::Validate);
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|domain name: {}|Start migration failed.", domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return OnStartMigrationResponseReceived();
}

MigrateSessionRc MigrationSession::OnStartMigrationResponseReceived()
{
    VIRTRUST_LOG_DEBUG("|OnStartMigrationResponseReceived|START|");
    char *cipher = nullptr;
    int cipherLen = 0;
    // 收集密码资源
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetVrootCipher start.", domainName_);
    auto ret = MigrationGetVrootCipher(uuid_.data(), uuid_.data(), &cipher, &cipherLen);
    // 成功码与非空指针不足以证明输出可用；负长度会在构造字符串时转成巨大的无符号长度。
    if (ret != 0 || cipher == nullptr || cipherLen <= 0) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Source, MigrationOperation::GetCipher,
                      ret != 0 ? MigrationErrorOrigin::Tsb : MigrationErrorOrigin::Internal, ret != 0, ret);
        if (cipher != nullptr) {
            free(cipher);
            cipher = nullptr;
        }
        VIRTRUST_LOG_ERROR(
            "|OnStartMigrationResponseReceived|END|returnF|domain name: {}|TSB: MigrationGetVRootCipher failed.",
            domainName_);
        if (ret == ERR_VM_NOT_STARTED) {
            VIRTRUST_LOG_ERROR("call MigrationGetVRootCipher failed: the VM has not been started yet.");
        }
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetVrootCipher success.", domainName_);

    std::string cipherStr(cipher, cipherLen);
    free(cipher);
    cipher = nullptr;

    // 收集虚机描述信息
    Description vmInfo;
    auto rc = GetVmInfo(vmInfo);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnStartMigrationResponseReceived|END|returnF|domain name: {}|Get VM description failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 进入传输阶段
    EnterState(State::Transferring);
    return SendTransferOnce(cipherStr, vmInfo);
}

// libvirt 离线迁移成功后再发送可信资源；两步跨节点操作不能合并成一个原子事务。
MigrateSessionRc MigrationSession::SendTransferOnce(const std::string &cipher, const Description &vmInfo)
{
    // 1.调用libvirt命令进行迁移
    VIRTRUST_LOG_DEBUG("|SendTransferOnce|START|");
    MigrateSessionRc rc = MigrateByLibvirt();
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||migrate by libvirt failed.");
        OnFail();
        return rc;
    }
    ConfirmStep(MigrationStep::LibvirtTransferred);

    // 2.传输数据
    protos::VRsourceInfoRequest req;
    req.set_uuid(uuid_);
    req.set_attempt_id(attemptId_);
    req.set_cipherdata(cipher);
    auto protosDesc = req.mutable_vtpcminfo();
    DescriptionToProto(vmInfo, protosDesc);

    protos::VRsourceInfoReply res;
    int32_t ret = rpcClient_->SendVRsourceData(RPC_TRANSFER_TIMEOUT, req, &res);
    // 传输数据失败
    if (ret != 0) {
        if (ret == RPC_TRANSPORT_FAILURE) {
            RecordFailure(MigrationStage::DataTransfer, MigrationSide::Source, MigrationOperation::NotifyPeer,
                          MigrationErrorOrigin::Grpc);
        } else if (res.has_diagnostic() && res.diagnostic().has_primary_error()) {
            const auto peer = FromProto(res.diagnostic(), VirtrustRc::ERROR).primaryError;
            RecordFailure(peer.stage, peer.side, peer.operation, peer.origin, peer.hasRawCode, peer.rawCode);
        } else {
            RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::Validate,
                          MigrationErrorOrigin::Internal);
        }
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to tansfer data for: {}, ret {}.", domainName_, ret);
        if (ret == RPC_TRANSPORT_FAILURE) {
            // 无有效回复时目的端可能仍在导入或已创建可信资源；不得并发撤销定义或发送失败通知。
            VIRTRUST_LOG_ERROR("Transfer result unknown: uuid={}, attempt={}; preserve both nodes for manual "
                               "verification", uuid_, attemptId_);
            EnterState(State::Failed);
            return MigrateSessionRc::ERROR;
        }
        // 只有确实收到目的端业务回复，才允许读取诊断判断“原本就有此 UUID”。
        const auto &peerError = res.diagnostic().primary_error();
        const bool duplicateVroot = ret != RPC_TRANSPORT_FAILURE && res.has_diagnostic() &&
                                    res.diagnostic().has_primary_error() &&
                                    peerError.operation() == protos::MIGRATION_OPERATION_CREATE_VROOT &&
                                    peerError.origin() == protos::MIGRATION_ERROR_ORIGIN_TSB &&
                                    peerError.has_raw_code() && peerError.raw_code() == ERR_DUPLICATE_UUID;
        if (duplicateVroot) {
            VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to tansfer data for: {}, already exist in dest",
                               domainName_);
        }
        UndoMigration(duplicateVroot ? ERR_DUPLICATE_UUID : 0);
        return MigrateSessionRc::ERROR;
    }

    return OnTransferResponseReceived(res.result() == 0);
}

// 目的端确认接收后依次提交源端 TSB、确认目的端收尾，最后才清理源端残留。
MigrateSessionRc MigrationSession::OnTransferResponseReceived(bool transferRet)
{
    // 对端校验数据失败
    VIRTRUST_LOG_DEBUG("|OnTransferResponseReceived|START|");
    if (!transferRet) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Internal);
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF||peer verify data faild: {}", domainName_);
        UndoMigration(0);
        return MigrateSessionRc::ERROR;
    }
    ConfirmStep(MigrationStep::DestinationDataAccepted);

    // 通知TSB迁移成功，如果调用失败，TSB虚机状态会保持 VM_MIGRATION
    auto rc = NotifyVRMigration(true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF|domain name: {}|Libvirt transfer succeeded but "
                           "MigrationNotify(success) failed; inspect TSB state manually.", domainName_);
        // 底层可能已产生不可逆副作用，不能在此发送失败通知或自动回滚。
        EnterState(State::Failed);
        return MigrateSessionRc::ERROR;
    }
    ConfirmStep(MigrationStep::SourceTsbCommitted);

    // 目的端先提交并释放会话资格；回复失败时保留源端资源，等待人工核查目的端结果。
    if (SendFinishedNotify(true) != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF|domain name: {}|Final destination "
                           "acknowledgment failed; inspect destination state manually.", domainName_);
        EnterState(State::Failed);
        return MigrateSessionRc::ERROR;
    }
    ConfirmStep(MigrationStep::DestinationConfirmed);
    // 目的端已完成，源端清理失败只影响本端结果，不反向通知或撤销目的端。
    if ((flags_ & MIGRATE_UNDEFINE_SOURCE) && CleanupSourceResources() != MigrateSessionRc::OK) {
        EnterState(State::Failed);
        return MigrateSessionRc::ERROR;
    }
    MarkSuccess();
    EnterState(State::Finished);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::SendFinishedNotify(bool success)
{
    VIRTRUST_LOG_DEBUG("|SendFinishedNotify|START|");
    protos::MigrateResultRequest req;
    req.set_result(success ? 0 : 1);
    req.set_uuid(uuid_);
    req.set_attempt_id(attemptId_);
    protos::MigrateResultReply res;
    auto ret = rpcClient_->NotifyVRMigrateResult(RPC_SIGNAL_TIMEOUT, req, &res);
    if (ret != 0) {
        if (success) {
            if (ret == RPC_TRANSPORT_FAILURE) {
                // 最终通知可能已完成：只读核查使用独立期限，不重新执行目的端业务。
                protos::QueryMigrationFinalResultRequest query;
                query.set_uuid(uuid_);
                query.set_attempt_id(attemptId_);
                protos::QueryMigrationFinalResultReply checked;
                // 先将查询结果预设为传输失败
                int32_t queryRc = RPC_TRANSPORT_FAILURE;
                try {
                    queryRc = rpcClient_->QueryMigrationFinalResult(RPC_SIGNAL_TIMEOUT, query, &checked);
                } catch (...) {
                    // 查询本身异常不改变原通知结果未知的保守结论。
                }
                if (queryRc == 0 && checked.state() == protos::FINAL_RESULT_COMPLETED_SUCCESS) {
                    VIRTRUST_LOG_WARN("Final migration reply lost but read-only query confirmed destination: "
                                      "uuid={}, attempt={}", uuid_, attemptId_);
                    return MigrateSessionRc::OK;
                }
                if (queryRc == 0 && checked.state() == protos::FINAL_RESULT_COMPLETED_FAILURE) {
                    RecordPeerFailure(checked.diagnostic(), VirtrustRc::ERROR, MigrationStage::DestinationCommit,
                                      MigrationOperation::NotifyTsb);
                    return MigrateSessionRc::ERROR;
                }
                RecordFailure(MigrationStage::DestinationCommit, MigrationSide::Source,
                              MigrationOperation::NotifyPeer, MigrationErrorOrigin::Grpc);
                // 未取得回复不等于目的端未提交；日志保留尝试身份，供两端人工核查。
                VIRTRUST_LOG_ERROR("Final migration reply unavailable: uuid={}, attempt={}; destination may have "
                                   "committed. Verify both nodes before manually retrying.", uuid_, attemptId_);
            } else {
                const auto businessRc = res.result() != 0 ? static_cast<VirtrustRc>(res.result()) : VirtrustRc::ERROR;
                RecordPeerFailure(res.diagnostic(), businessRc, MigrationStage::DestinationCommit,
                                  MigrationOperation::NotifyPeer);
            }
        } else {
            AddCompensationError(MigrationStage::DestinationCommit, MigrationSide::Source,
                                 MigrationOperation::NotifyPeer,
                                 ret == RPC_TRANSPORT_FAILURE ? MigrationErrorOrigin::Grpc : MigrationErrorOrigin::Internal);
        }
        VIRTRUST_LOG_ERROR("|SendFinishedNotify|END|returnF|domain name: {}|Send notify failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    return OnFinishedResponseReceived(res.result() == 0);
}

MigrateSessionRc MigrationSession::OnFinishedResponseReceived(bool finished)
{
    VIRTRUST_LOG_DEBUG("|OnFinishedResponseReceived|START|");
    if (!finished) {
        VIRTRUST_LOG_ERROR("|OnFinishedResponseReceived|END|returnF|domain name: {}|Destination rejected final "
                           "migration notification.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetExchangePkAndReport(protos::EXchangePkAndReportRequest *req,
                                                          protos::EXchangePkAndReportReply *res)
{
    VIRTRUST_LOG_DEBUG("|GetExchangePkAndReport|START|");
    auto uuid = uuid_;
    char *cert = nullptr;
    int certLen = 0;
    char *pubKey = nullptr;
    int pubKeyLen = 0;

    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetCert start.", domainName_);
    int ret = MigrationGetCert(uuid.data(), &cert, &certLen, &pubKey, &pubKeyLen);
    // 底层通过 malloc 转交所有权；先接管两个缓冲区，后续校验或字符串分配异常都能释放。
    std::unique_ptr<char, decltype(&std::free)> certOwner(cert, &std::free);
    std::unique_ptr<char, decltype(&std::free)> pubKeyOwner(pubKey, &std::free);
    if (ret != 0 || cert == nullptr || pubKey == nullptr || certLen <= 0 || pubKeyLen <= 0) {
        // 底层返回成功但输出无效时也属错误，不能虚构一个 TSB 原始错误码。
        RecordFailure(MigrationStage::KeyExchange,
                      role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                      MigrationOperation::GetCertificate,
                      ret != 0 ? MigrationErrorOrigin::Tsb : MigrationErrorOrigin::Internal, ret != 0, ret);
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|TSB: MigrationGetCert failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetCert success.", domainName_);

    std::string certStr(certOwner.get(), static_cast<size_t>(certLen));
    std::string pubKeyStr(pubKeyOwner.get(), static_cast<size_t>(pubKeyLen));
    certOwner.reset();
    pubKeyOwner.reset();

    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: GetReport start.", domainName_);
    trust_report_new hostReport;
    trust_report_new vmReport;
    ret = GetReport(uuid.data(), uuid.data(), &hostReport, &vmReport);
    if (ret != 0) {
        RecordFailure(MigrationStage::KeyExchange,
                      role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                      MigrationOperation::GetReport, MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|Get local report failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: GetReport success.", domainName_);

    if (role_ == Role::Initiator) {
        if (req == nullptr) {
            VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|req is null.", domainName_);
            return MigrateSessionRc::ERROR;
        }
        req->set_domainname(domainName_);
        req->set_uuid(uuid);
        req->set_attempt_id(attemptId_);
        req->set_cert(certStr);
        req->set_publickey(pubKeyStr);
        auto hostReportProto = req->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = req->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    } else {
        if (res == nullptr) {
            VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|res is null.", domainName_);
            return MigrateSessionRc::ERROR;
        }
        res->set_domainname(domainName_);
        res->set_uuid(uuid);
        res->set_cert(certStr);
        res->set_publickey(pubKeyStr);
        auto hostReportProto = res->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = res->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::VerifyCertificate(std::string uuid, std::string cert, std::string pubkey)
{
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationCheckPeerPk start.", domainName_);
    int ret = MigrationCheckPeerPk(uuid.data(), cert.data(), pubkey.data());
    if (ret != 0) {
        RecordFailure(MigrationStage::KeyExchange,
                      role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                      MigrationOperation::VerifyCertificate, MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_DEBUG("|VerifyCertificate|END|returnF|domain name: {}|TSB: MigrationCheckPeerPk failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationCheckPeerPk success.", domainName_);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::VerifyHostAndVmReport(const protos::TrustReportNew &hostProtoReport,
                                                         const protos::TrustReportNew &vmProtoReport,
                                                         bool isDestEnd)
{
    VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|START|");
    trust_report_new hostReport;
    bool success = ReportFromProto(hostProtoReport, hostReport);
    if (!success) {
        RecordFailure(MigrationStage::KeyExchange,
                      role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                      MigrationOperation::VerifyReport, MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: report from proto failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    int ret = 0;
    // 只有目的端需要校验 vmReport，源端该参数直接传入nullptr
    if (isDestEnd) {
        trust_report_new vmReport;
        success = ReportFromProto(vmProtoReport, vmReport);
        if (!success) {
            RecordFailure(MigrationStage::KeyExchange, MigrationSide::Destination,
                          MigrationOperation::VerifyReport, MigrationErrorOrigin::Validation);
            VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: report from proto failed.",
                               domainName_);
            return MigrateSessionRc::ERROR;
        }
        VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: VerifyTrustReport start.", domainName_);
        ret = VerifyTrustReport(uuid_.data(), uuid_.data(), &hostReport, &vmReport);
    } else {
        ret = VerifyTrustReport(uuid_.data(), uuid_.data(), &hostReport, nullptr);
    }
    if (ret != 0) {
        RecordFailure(MigrationStage::KeyExchange,
                      role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                      MigrationOperation::VerifyReport, MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: VerifyTrustReport failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: VerifyTrustReport success.", domainName_);
    return MigrateSessionRc::OK;
}

// 调用libvirt接口迁移
MigrateSessionRc MigrationSession::MigrateByLibvirt()
{
    VIRTRUST_LOG_DEBUG("|MigrateByLibvirt|START|");
    auto &libvirt = Libvirt::GetInstance();

    std::unique_ptr<ConnCtx> destConn;
    auto rc = GetVirConnContext(destUri_, destConn);
    if (rc != MigrateSessionRc::OK) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::ConnectLibvirt,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to get virt connect: {}", destUri_);
        return rc;
    }

    std::unique_ptr<ConnCtx> localConn;
    rc = GetVirConnContext(localUri_, localConn);
    if (rc != MigrateSessionRc::OK) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::ConnectLibvirt,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to get virt connect: {}", localUri_);
        return rc;
    }

    auto domain = std::make_unique<DomainCtx>(localConn, domainName_);
    if (domain->Get() == nullptr) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::LookupDomain,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to find domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    if (destConn->Get() == nullptr) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::ConnectLibvirt,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to find desturl: {}", destUri_);
        return MigrateSessionRc::ERROR;
    }
    // 准入预检查后仍可能被外部 libvirt 操作替换同名定义；迁移前必须重新核对实际域身份。
    char sourceUuid[sizeof(Description::uuid)]{};
    if (libvirt.virDomainGetUUIDString(domain->Get(), sourceUuid) < 0) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::CheckIdentity,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|Identity|Failed to read source domain UUID: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    if (uuid_ != sourceUuid) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::CheckIdentity,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|Identity|Source domain UUID changed before transfer: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    auto *domainPtr = libvirt.virDomainMigrate3(domain->Get(), destConn->Get(), nullptr, 0,
                                                GetFlagCleard(flags_, MIGRATE_UNDEFINE_SOURCE));
    if (domainPtr == nullptr) {
        RecordFailure(MigrationStage::LibvirtTransfer, MigrationSide::Source, MigrationOperation::MigrateLibvirt,
                      MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to migrate domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    libvirt.virDomainFree(domainPtr);

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVirConnContext(const std::string &uri, std::unique_ptr<ConnCtx> &outConn)
{
    VIRTRUST_LOG_DEBUG("|GetVirConnContext|START|");
    auto conn = std::make_unique<ConnCtx>();
    if (!conn->SetUri(uri)) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||destUri is not valid: {}", uri);
        return MigrateSessionRc::ERROR;
    }

    conn->Connect();
    if (conn->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to establish connection to: {}", uri);
        return MigrateSessionRc::ERROR;
    }

    // 成功了再把拥有权交出去
    outConn = std::move(conn);
    return MigrateSessionRc::OK;
}

// 仅在数据传输失败后尽力补偿；动作失败逐项记录，不能据此宣称两端已恢复原状。
void MigrationSession::UndoMigration(int32_t ret)
{
    VIRTRUST_LOG_DEBUG("|UndoMigration|START|");
    // 防止server端误调
    if (role_ != Role::Initiator) {
        return;
    }
    // 对端已存在 不删除
    if (ret != ERR_DUPLICATE_UUID) {
        // 1.基于uri删除libvirt虚拟机
        UndefineVirtDomainBaseUri(destUri_);
    }

    // 2.通知TSB迁移失败
    NotifyVRMigration(false);

    // 3.通知peer迁移失败，并进行清理
    OnFail();
}

// 基于uri删除libvirt虚拟机
MigrateSessionRc MigrationSession::UndefineVirtDomainBaseUri(const std::string &uri)
{
    VIRTRUST_LOG_DEBUG("|UndefineVirtDomainBaseUri|START|");
    std::unique_ptr<ConnCtx> destConn;
    auto rc = GetVirConnContext(uri, destConn);
    if (rc != MigrateSessionRc::OK) {
        AddCompensationError(MigrationStage::DataTransfer, MigrationSide::Destination,
                             MigrationOperation::ConnectLibvirt, MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|UndefineVirtDomainBaseUri|END|returnF||failed to get virt connect: {}", uri);
        return rc;
    }

    auto destDomain = std::make_unique<DomainCtx>(destConn, domainName_);
    if (destDomain->Get() == nullptr) {
        AddCompensationError(MigrationStage::DataTransfer, MigrationSide::Destination,
                             MigrationOperation::LookupDomain, MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("|UndefineVirtDomainBaseUri|END|returnF|failed to find destDomain: {}, uri: {}", domainName_,
                           uri);
        return MigrateSessionRc::ERROR;
    }

    auto &libvirt = Libvirt::GetInstance();
    // 目的端同名定义可能已被替换；只允许取消本次迁移 UUID 对应的定义。
    char destinationUuid[sizeof(Description::uuid)]{};
    if (libvirt.virDomainGetUUIDString(destDomain->Get(), destinationUuid) < 0) {
        AddCompensationError(MigrationStage::DataTransfer, MigrationSide::Destination,
                             MigrationOperation::CheckIdentity, MigrationErrorOrigin::Libvirt);
        VIRTRUST_LOG_ERROR("Cannot verify destination domain UUID before compensation: name={}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    if (uuid_ != destinationUuid) {
        AddCompensationError(MigrationStage::DataTransfer, MigrationSide::Destination,
                             MigrationOperation::CheckIdentity, MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("Destination domain UUID changed before compensation: name={}, expected={}",
                           domainName_, uuid_);
        return MigrateSessionRc::ERROR;
    }
    const int undefineRet = libvirt.virDomainUndefineFlags(destDomain->Get(), DOMAIN_UNDEFINE_NVRAM);
    if (undefineRet != 0) {
        AddCompensationError(MigrationStage::DataTransfer, MigrationSide::Destination,
                             MigrationOperation::UndefineDomain, MigrationErrorOrigin::Libvirt, true, undefineRet);
        VIRTRUST_LOG_INFO("|UndefineVirtDomainBaseUri|END|returnF|undefine dest domain: {} failed, uri: {}",
                          domainName_, uri);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

// 目的端已确认完成，源端清理失败只形成 PARTIAL，不反向撤销目的端结果。
MigrateSessionRc MigrationSession::CleanupSourceResources()
{
    // 从守护进程启动时的配置读取总尝试次数；直接构造的会话同样有三次缺省值。
    const auto attempts = ConfigMgr::Instance().GetLinkConfig().sourceCleanupMaxAttempts;
    if (attempts < 1 || attempts > MAX_SOURCE_CLEANUP_MAX_ATTEMPTS) {
        RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::Validate,
                      MigrationErrorOrigin::Internal, false, 0, MigrationOutcome::Partial);
        VIRTRUST_LOG_ERROR("Invalid source cleanup attempt limit: uuid={}, attempts={}", uuid_, attempts);
        return MigrateSessionRc::ERROR;
    }
    std::unique_ptr<ConnCtx> sourceConn;
    if (GetVirConnContext(localUri_, sourceConn) != MigrateSessionRc::OK) {
        RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::ConnectLibvirt,
                      MigrationErrorOrigin::Libvirt, false, 0, MigrationOutcome::Partial);
        VIRTRUST_LOG_ERROR("Source definition cleanup connection failed: uuid={}, uri={}; inspect source manually",
                           uuid_, localUri_);
        return MigrateSessionRc::ERROR;
    }
    auto sourceDomain = std::make_unique<DomainCtx>(sourceConn, domainName_);
    if (sourceDomain->Get() == nullptr) {
        RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::LookupDomain,
                      MigrationErrorOrigin::Libvirt, false, 0, MigrationOutcome::Partial);
        VIRTRUST_LOG_ERROR("Source definition cleanup lookup failed: uuid={}, name={}; inspect source manually", uuid_,
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    auto &libvirt = Libvirt::GetInstance();
    char sourceUuid[sizeof(Description::uuid)]{};
    // 删除前复核定义身份，避免同名定义被外部进程替换后误删另一台虚机。
    if (libvirt.virDomainGetUUIDString(sourceDomain->Get(), sourceUuid) < 0 || uuid_ != sourceUuid) {
        RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::CheckIdentity,
                      MigrationErrorOrigin::Libvirt, false, 0, MigrationOutcome::Partial);
        VIRTRUST_LOG_ERROR("Source definition identity changed before cleanup: expected uuid={}, name={}; inspect source "
                           "manually", uuid_, domainName_);
        return MigrateSessionRc::ERROR;
    }

    int lastTsbRet = 0;
    for (uint16_t attempt = 1; attempt <= attempts; ++attempt) {
        lastTsbRet = RemoveVRoot(uuid_.data());
        if (lastTsbRet == 0) {
            break;
        }
        VIRTRUST_LOG_WARN("Source VRoot removal failed: uuid={}, attempt={}/{}, tsbRet={}", uuid_, attempt, attempts,
                          lastTsbRet);
    }
    if (lastTsbRet != 0) {
        RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::RemoveVRoot,
                      MigrationErrorOrigin::Tsb, true, lastTsbRet, MigrationOutcome::Partial);
        VIRTRUST_LOG_ERROR("Source VRoot removal exhausted: uuid={}, attempts={}, tsbRet={}; inspect source manually",
                           uuid_, attempts, lastTsbRet);
        return MigrateSessionRc::ERROR;
    }
    ConfirmStep(MigrationStep::SourceVRootRemoved);

    int lastLibvirtRet = 0;
    for (uint16_t attempt = 1; attempt <= attempts; ++attempt) {
        lastLibvirtRet = libvirt.virDomainUndefineFlags(sourceDomain->Get(), DOMAIN_UNDEFINE_NVRAM);
        if (lastLibvirtRet >= 0) {
            ConfirmStep(MigrationStep::SourceDefinitionUndefined);
            return MigrateSessionRc::OK;
        }
        VIRTRUST_LOG_WARN("Source definition undefine failed: uuid={}, attempt={}/{}, libvirtRet={}", uuid_, attempt,
                          attempts, lastLibvirtRet);
    }
    RecordFailure(MigrationStage::SourceCleanup, MigrationSide::Source, MigrationOperation::UndefineDomain,
                  MigrationErrorOrigin::Libvirt, true, lastLibvirtRet, MigrationOutcome::Partial);
    VIRTRUST_LOG_ERROR("Source definition undefine exhausted: uuid={}, attempts={}, libvirtRet={}; inspect source "
                       "manually", uuid_, attempts, lastLibvirtRet);
    return MigrateSessionRc::ERROR;
}

// 通知TSB迁移结果
MigrateSessionRc MigrationSession::NotifyVRMigration(bool success)
{
    VIRTRUST_LOG_DEBUG("|NotifyVRMigration|START|");
    auto status = success ? 0 : -1;
    auto ret = MigrationNotify(uuid_.data(), status);
    if (ret != 0) {
        if (success) {
            RecordFailure(role_ == Role::Initiator ? MigrationStage::SourceCommit : MigrationStage::DestinationCommit,
                          role_ == Role::Initiator ? MigrationSide::Source : MigrationSide::Destination,
                          MigrationOperation::NotifyTsb, MigrationErrorOrigin::Tsb, true, ret);
        } else if (role_ == Role::Initiator) {
            AddCompensationError(MigrationStage::SourceCommit, MigrationSide::Source, MigrationOperation::NotifyTsb,
                                 MigrationErrorOrigin::Tsb, true, ret);
        }
        VIRTRUST_LOG_INFO("|NotifyVRMigration|END|returnF|domainName:{}, migration statu: {}|Notify TSB failed.",
                          domainName_, success);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVmInfo(Description &vmInfo)
{
    Description *raw = nullptr;
    int vNums = 0;
    int ret = GetVRoots(&vNums, &raw);

    std::unique_ptr<Description, void (*)(Description *)> vInfos(raw, [](Description *p) {
        if (p)
            free(p);
    });

    if (ret != 0 || raw == nullptr || vNums <= 0) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Source, MigrationOperation::GetDescription,
                      ret != 0 ? MigrationErrorOrigin::Tsb : MigrationErrorOrigin::Internal, ret != 0, ret);
        VIRTRUST_LOG_INFO("|GetVmInfo|END|returnF||Get all vm descriptions failed.");
        return MigrateSessionRc::ERROR;
    }

    const std::string &uuid = uuid_;

    for (int i = 0; i < vNums; ++i) {
        if (std::strncmp(vInfos.get()[i].uuid, uuid.c_str(), sizeof(vInfos.get()[i].uuid)) == 0) {
            vmInfo = vInfos.get()[i];
            return MigrateSessionRc::OK;
        }
    }

    VIRTRUST_LOG_ERROR("|GetVmInfo|END|returnF|uuid: {}|VM with specified UUID not found.", uuid);
    RecordFailure(MigrationStage::DataTransfer, MigrationSide::Source, MigrationOperation::GetDescription,
                  MigrationErrorOrigin::Validation);
    return MigrateSessionRc::ERROR;
}

MigrateSessionRc MigrationSession::ExportTcm2Key(std::string &tcm2Key)
{
    char *key = nullptr;
    int keyLen = 0;

    VIRTRUST_LOG_DEBUG("|domain name: {} |TSB: TransDupPub export start.", domainName_);
    auto ret = TransDupPub(EN_EXPORT, nullptr, &key, &keyLen, nullptr, 0);
    if (ret != 0 || key == nullptr || keyLen <= 0) {
        // 输出缺失和底层非零返回分开，避免把成功码 0 作为失败原因展示。
        RecordFailure(MigrationStage::KeyExchange, MigrationSide::Destination, MigrationOperation::ExportKey,
                      ret != 0 ? MigrationErrorOrigin::Tsb : MigrationErrorOrigin::Internal, ret != 0, ret);
        if (key != nullptr) {
            free(key);
        }
        VIRTRUST_LOG_ERROR("|ExportTcm2Key|END|returnF|domain name: {} |TSB: TransDupPub export failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {} |TSB: TransDupPub export success.", domainName_);

    tcm2Key = std::string(key, keyLen);
    free(key);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::ImportTcm2Key(std::string_view tcm2Key)
{
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: TransDupPub import start.", domainName_);
    auto ret = TransDupPub(EN_IMPORT, uuid_.data(), nullptr, nullptr, std::string(tcm2Key).data(), tcm2Key.size());
    if (ret != 0) {
        RecordFailure(MigrationStage::KeyExchange, MigrationSide::Source, MigrationOperation::ExchangeKey,
                      MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_ERROR("|ImportTcm2Key|END|returnF|domain name: {}|TSB: TransDupPub import failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: TransDupPub import success.", domainName_);

    return MigrateSessionRc::OK;
}

void MigrationSession::EnterState(State s)
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (cleanedUp_) {
        return;
    }
    state_ = s;
    CancelTimer();

    // 终态不再开定时器
    if (s == State::Failed || s == State::Finished) {
        return;
    }

    StartTimerFor(s);
}

static std::chrono::seconds TimeoutForState(MigrationSession::State s)
{
    switch (s) {
        case MigrationSession::State::Init:
            return std::chrono::seconds(10);
        case MigrationSession::State::WaitingKey:
            return std::chrono::seconds(30);
        case MigrationSession::State::Transferring:
        case MigrationSession::State::AwaitingFinish:
            return std::chrono::seconds(60);
        default:
            return std::chrono::seconds(60);
    }
}

void MigrationSession::StartTimerFor(State s)
{
    timerActive_.store(true);
    auto dur = TimeoutForState(s);
    std::weak_ptr<MigrationSession> weakSelf = weak_from_this();
    const auto generation = timerGeneration_;
    timer_.Start(dur, [weakSelf, s, generation] {
        if (auto self = weakSelf.lock()) {
            self->OnTimeoutForGeneration(s, generation);
        }
    });
}

void MigrationSession::CancelTimer()
{
    ++timerGeneration_;
    timerActive_.store(false);
    timer_.Cancel();
}

void MigrationSession::OnTimeout(State stateWhenSet)
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    OnTimeoutForGeneration(stateWhenSet, timerGeneration_);
}

void MigrationSession::OnTimeoutForGeneration(State stateWhenSet, uint64_t generation)
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (cleanedUp_ || !timerActive_.load() || state_ != stateWhenSet || timerGeneration_ != generation) {
        return;
    }
    if (role_ == Role::Initiator) {
        // 源端超时仅记录诊断，实际业务结果由同步执行线程决定。
        CancelTimer();
        try {
            VIRTRUST_LOG_WARN("|SourceMigration|Timeout|uuid: {}, domain name: {}, stage: {}|Stage deadline "
                              "expired; migration continues until its actual result is known.",
                              uuid_, domainName_, static_cast<int>(stateWhenSet));
        } catch (...) {
            // 定时器线程不得因诊断异常而终止进程。
        }
        return;
    }
    EnterState(State::Failed);
    Cleanup();
}

void MigrationSession::Cleanup()
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (cleanedUp_) {
        return;
    }
    cleanedUp_ = true;
    CancelTimer();
    SessionManager::GetInstance().RemoveSessionIfCurrent(uuid_, this);
    admission_.Release();
    // 诊断失败不得阻止资格释放，或使终态清理被再次执行。
    try {
        VIRTRUST_LOG_DEBUG("|Cleanup|END|uuid: {}", uuid_);
    } catch (...) {
    }
}

void MigrationSession::OnFail()
{
    std::lock_guard<std::recursive_mutex> guard(operationMutex_);
    if (cleanedUp_) {
        return;
    }
    VIRTRUST_LOG_DEBUG("|OnFail|START|");
    // 未确认 Prepare 已被接受时不发送失败通知，避免误清理同 UUID 的旧会话。
    if (role_ == Role::Initiator && destinationAccepted_) {
        destinationAccepted_ = false;
        MigrateSessionRc sendRet = SendFinishedNotify(false);
        if (sendRet != MigrateSessionRc::OK) {
            VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF| domain name: {}|SendFinishedNotify failed.", domainName_);
        }
    }

    // 进入失败状态
    EnterState(State::Failed);
}

MigrateSessionRc MigrationSession::OnMigrateRequestReceived()
{
    return RunResponderStep([this] { return PrepareResponder(); });
}

MigrateSessionRc MigrationSession::PrepareResponder()
{
    VIRTRUST_LOG_DEBUG("|OnMigrateRequestReceived|START|");
    if (state_ != State::Init) {
        return MigrateSessionRc::ERROR;
    }
    MigrationError capacityFailure;
    if (CheckMaxDomainCount(&capacityFailure) != VirtrustRc::OK) {
        RecordFailure(MigrationStage::Prepare, MigrationSide::Destination, capacityFailure.operation,
                      capacityFailure.origin, capacityFailure.hasRawCode, capacityFailure.rawCode,
                      MigrationOutcome::FailedBeforeEffect);
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::WaitingKey);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                                protos::EXchangePkAndReportReply *response)
{
    return RunResponderStep([&] { return ExchangeResponderKey(request, response); });
}

MigrateSessionRc MigrationSession::ExchangeResponderKey(const protos::EXchangePkAndReportRequest *request,
                                                        protos::EXchangePkAndReportReply *response)
{
    VIRTRUST_LOG_DEBUG("|OnExchangeKeyRequestReceived|START|");
    if (state_ != State::WaitingKey) {
        RecordFailure(MigrationStage::KeyExchange, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Waiting for exchanging key timeout.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 1. 获取本端证书和报告
    MigrateSessionRc rc = GetExchangePkAndReport(nullptr, response);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Get public key and report failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 2. 校验对端证书
    rc = VerifyCertificate(request->uuid(), request->cert(), request->publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer cert failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 3. 校验对端报告
    rc = VerifyHostAndVmReport(request->hostreport(), request->vmreport(), true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 4. 导出tcm2密钥，返回给源
    std::string tcm2Key;
    rc = ExportTcm2Key(tcm2Key);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Export tcm2 key failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    response->set_tcm2key(tcm2Key);

    // 等待对端校验证书后的进一步信号：开始迁移信号
    EnterState(State::CertVerify);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnStartMigrationRequestReceived()
{
    return RunResponderStep([this] { return BeginResponderTransfer(); });
}

MigrateSessionRc MigrationSession::BeginResponderTransfer()
{
    VIRTRUST_LOG_DEBUG("|OnStartMigrationRequestReceived|START|");
    if (state_ != State::CertVerify) {
        RecordFailure(MigrationStage::Start, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("|OnStartMigrationRequestReceived|END|returnF|domain name: {}|Waiting for starting "
                           "migration signal timeout.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 等待对端发起数据传数
    EnterState(State::Transferring);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnTransferDataRequestReceived(const protos::VRsourceInfoRequest *request)
{
    return RunResponderStep([&] { return ImportResponderData(request); });
}

MigrateSessionRc MigrationSession::ImportResponderData(const protos::VRsourceInfoRequest *request)
{
    VIRTRUST_LOG_DEBUG("|OnTransferDataRequestReceived|START|");
    if (state_ != State::Transferring) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|Waiting for transfering timeout.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 先解码并核对会话身份，再调用不可撤销的密文导入与可信资源创建接口。
    const auto &protosDesc = request->vtpcminfo();
    Description vmInfo;
    bool success = DescriptionFromProto(protosDesc, vmInfo);
    if (!success) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: description from proto failed.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }
    const auto &descriptionUuid = protosDesc.uuid();
    // 当前源端可传 36 字节 UUID，也可附带一个结尾 NUL；其余附加字节不得被截断忽略。
    const bool uuidMatches = descriptionUuid == uuid_ ||
        (descriptionUuid.size() == uuid_.size() + 1 && descriptionUuid.back() == '\0' &&
         descriptionUuid.compare(0, uuid_.size(), uuid_) == 0);
    if (request->uuid() != uuid_ || !uuidMatches || protosDesc.name() != domainName_) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::CheckIdentity,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("Destination transfer identity mismatch: expected uuid={}, name={}", uuid_, domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 底层接口参数可写；传入局部副本，不能让其改写会话保存的 UUID。
    auto uuid = uuid_;
    auto cipherData = request->cipherdata();
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationImportVrootCipher start", domainName_);
    auto ret = MigrationImportVrootCipher(uuid.data(), uuid.data(), cipherData.data(), cipherData.size());
    if (ret != 0) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::ImportCipher,
                      MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: MigrationImportVrootCipher failed.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationImportVrootCipher success.", domainName_);

    vmInfo.state = VM_SHUTUP;
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: CreateVRoot start", domainName_);
    ret = CreateVRoot(&vmInfo);
    if (ret != 0) {
        RecordFailure(MigrationStage::DataTransfer, MigrationSide::Destination, MigrationOperation::CreateVRoot,
                      MigrationErrorOrigin::Tsb, true, ret);
        VIRTRUST_LOG_ERROR("|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: CreateVRoot failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: CreateVRoot success", domainName_);

    // 密文导入及可信资源创建均成功后，才允许目的端接受最终成功通知。
    EnterState(State::AwaitingFinish);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnFinishedRequestReceived(bool finished)
{
    return RunResponderStep([&] { return FinishResponder(finished); });
}

MigrateSessionRc MigrationSession::FinishResponder(bool finished)
{
    VIRTRUST_LOG_DEBUG("|OnFinishedRequestReceived|START|");
    if (!finished) {
        VIRTRUST_LOG_ERROR("|OnFinishedRequestReceived|END|returnF|domain name: {}|Migrate failed.", domainName_);
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::OK;
    }
    if (state_ != State::AwaitingFinish) {
        RecordFailure(MigrationStage::DestinationCommit, MigrationSide::Destination, MigrationOperation::Validate,
                      MigrationErrorOrigin::Validation);
        VIRTRUST_LOG_ERROR("|OnFinishedRequestReceived|END|returnF|domain name: {}"
            "|Resources are not ready.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|OnFinishedRequestReceived|END|returnS|domain name: {}|Migrate success.", domainName_);

    // 通知TSB迁移成功，如果调用失败，TSB虚机状态会保持 VM_MIGRATION
    auto rc = NotifyVRMigration(true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_WARN("|OnFinishedRequestReceived|END|returnF|domain name: {}|Migrate libvirt and tsb resource "
                          "success but MigrationNotify(success) failed, please resolve tsb status.",
                          domainName_);
        return MigrateSessionRc::ERROR;
    }

    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}
} // namespace virtrust
