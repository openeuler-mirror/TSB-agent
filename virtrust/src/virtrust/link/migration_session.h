/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "tsb_agent/tsb_agent.h"

#include "virtrust/api/context.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_result.h"
#include "virtrust/utils/async_timer.h"

namespace virtrust {

enum class MigrateSessionRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

class MigrationSession : public std::enable_shared_from_this<MigrationSession> {
public:
    enum class Role {
        Initiator, // 客户端状态
        Responder  // 服务端状态
    };

    enum class State { Init, WaitingKey, CertVerify, Transferring, AwaitingFinish, Finished, Failed };

    MigrationSession(Role role, const std::string &uuid, const std::string &domainName,
                     const std::string &destUri = "", const std::string &localUri = "", const unsigned int flags = 0,
                     NodeAdmission admission = {});

    // 主动方起步
    MigrateSessionRc Start();

    // 定时器触发时调用
    void OnTimeout(State stateWhenSet);

    // 标记失败；源端按接收确认情况尝试通知目的端，最终清理由调用方收尾。
    void OnFail();

    // 让manager删掉自己
    void Cleanup();

    // 返回已确认的迁移诊断快照；会话清理后仍可由当前持有者读取。
    MigrationResult Diagnostic() const;

    const std::string &Id() const
    {
        return uuid_;
    }

    // 仅 Initiator 使用：注入 RPC 客户端（会话拥有其生命周期）
    void SetRpcClient(std::unique_ptr<RpcClient> rpc)
    {
        rpcClient_ = std::move(rpc);
    }

    // 响应方使用
    MigrateSessionRc OnMigrateRequestReceived();

    MigrateSessionRc OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                  protos::EXchangePkAndReportReply *response);

    MigrateSessionRc OnStartMigrationRequestReceived();

    MigrateSessionRc OnTransferDataRequestReceived(const protos::VRsourceInfoRequest *request);

    MigrateSessionRc OnFinishedRequestReceived(bool finished);

private:
    // 响应方业务失败与资格清理必须在同一会话锁范围内完成，避免等待中的 RPC 插入。
    template <typename Action>
    MigrateSessionRc RunResponderStep(Action &&action)
    {
        std::lock_guard<std::recursive_mutex> guard(operationMutex_);
        if (role_ != Role::Responder || cleanedUp_) {
            return MigrateSessionRc::ERROR;
        }
        if (state_ == State::Failed || state_ == State::Finished) {
            Cleanup();
            return MigrateSessionRc::ERROR;
        }
        try {
            const auto result = action();
            if (result != MigrateSessionRc::OK) {
                EnterState(State::Failed);
                Cleanup();
            }
            return result;
        } catch (...) {
            EnterState(State::Failed);
            Cleanup();
            throw;
        }
    }

    // 具体阶段动作由公开入口在统一锁与终态边界内调用。
    MigrateSessionRc PrepareResponder();
    MigrateSessionRc ExchangeResponderKey(const protos::EXchangePkAndReportRequest *request,
                                          protos::EXchangePkAndReportReply *response);
    MigrateSessionRc BeginResponderTransfer();
    MigrateSessionRc ImportResponderData(const protos::VRsourceInfoRequest *request);
    MigrateSessionRc FinishResponder(bool finished);

    // 这几个是收到对端应答时要调用的
    MigrateSessionRc OnMigrateResponseReceived();

    MigrateSessionRc OnExchangeKeyResponseReceived(protos::EXchangePkAndReportReply &res);

    MigrateSessionRc OnStartMigrationResponseReceived();

    MigrateSessionRc OnTransferResponseReceived(bool finished);

    MigrateSessionRc OnFinishedResponseReceived(bool finished);

    void EnterState(State s);

    void StartTimerFor(State s);

    void CancelTimer();

    // 定时器携带代数，避免旧回调在同一状态重新计时后误清理新状态。
    void OnTimeoutForGeneration(State stateWhenSet, uint64_t generation);

    // 主动方要发的几步
    MigrateSessionRc SendMigrateRequest();

    MigrateSessionRc SendExchangeKey();

    MigrateSessionRc SendStartMigration();

    MigrateSessionRc SendTransferOnce(const std::string &cipher, const Description &vmInfo);

    MigrateSessionRc SendFinishedNotify(bool success);

    // 辅助函数
    MigrateSessionRc GetExchangePkAndReport(protos::EXchangePkAndReportRequest *req,
                                            protos::EXchangePkAndReportReply *res);

    MigrateSessionRc VerifyCertificate(std::string uuid, std::string cert, std::string pubkey);

    MigrateSessionRc VerifyHostAndVmReport(const protos::TrustReportNew &hostReport,
                                           const protos::TrustReportNew &vmReport,
                                           bool isDestEnd);

    MigrateSessionRc GetVmInfo(Description &vmInfo);

    MigrateSessionRc MigrateByLibvirt();

    MigrateSessionRc GetVirConnContext(const std::string &uri, std::unique_ptr<ConnCtx> &outConn);

    void UndoMigration(int32_t result);

    MigrateSessionRc UndefineVirtDomainBaseUri(const std::string &uri);

    // 目的端明确完成后，先删源端可信资源，再删源端虚机定义；两步各自有限尝试。
    MigrateSessionRc CleanupSourceResources();

    MigrateSessionRc NotifyVRMigration(bool success);

    void RecordFailure(MigrationStage stage, MigrationSide side, MigrationOperation operation,
                       MigrationErrorOrigin origin, bool hasRawCode = false, int32_t rawCode = 0,
                       MigrationOutcome outcome = MigrationOutcome::Unknown);

    // 仅在收到有效业务回复后合并目的端根因；不以远端位集覆盖源端已确认步骤。
    void RecordPeerFailure(const protos::MigrationDiagnostic &diagnostic, VirtrustRc rc,
                           MigrationStage fallbackStage, MigrationOperation fallbackOperation);

    void ConfirmStep(MigrationStep step);
    void MarkSuccess();
    void AddCompensationError(MigrationStage stage, MigrationSide side, MigrationOperation operation,
                              MigrationErrorOrigin origin, bool hasRawCode = false, int32_t rawCode = 0) noexcept;

    MigrateSessionRc ExportTcm2Key(std::string &tcm2Key);

    MigrateSessionRc ImportTcm2Key(std::string_view tcm2Key);

private:
    Role role_;
    State state_;
    std::string uuid_;
    std::string domainName_;
    std::string destUri_;
    std::string localUri_;
    unsigned int flags_;

    // 响应方跨 RPC 持有目的端独占资格；与状态、定时器和清理共用同一同步边界。
    NodeAdmission admission_;
    mutable std::recursive_mutex operationMutex_;
    uint64_t timerGeneration_ = 0;
    bool cleanedUp_ = false;
    MigrationResult result_;

    // 仅 Initiator 侧使用
    std::unique_ptr<RpcClient> rpcClient_;
    // 记录本次 Prepare 已收到成功应答，阻止未确认接收时发送失败通知；不提供跨尝试身份校验。
    bool destinationAccepted_ = false;

    std::atomic<bool> timerActive_{false};

    AsyncTimer timer_;
};

class SessionManager {
public:
    static SessionManager &GetInstance()
    {
        static SessionManager instance;
        return instance;
    }

    // 禁止拷贝和移动
    SessionManager(const SessionManager &) = delete;

    SessionManager &operator=(const SessionManager &) = delete;

    // 创建并托管一个会话，调用方通过共享所有权保证使用期间对象存活
    std::shared_ptr<MigrationSession> CreateSession(MigrationSession::Role role, const std::string &uuid,
                                                    const std::string &domainName, const std::string &destUri,
                                                    const std::string &localUri, const unsigned int flags,
                                                    NodeAdmission admission = {});

    // 查找会话（比如 gRPC handler 用这个）
    std::shared_ptr<MigrationSession> GetSession(const std::string &uuid);

    // 会话结束时移除 manager 持有的引用；对象在最后一个使用者释放后销毁
    void RemoveSession(const std::string &uuid);

    // 只删除仍指向本会话的登记，防止旧回调误删同 UUID 的新任务。
    void RemoveSessionIfCurrent(const std::string &uuid, const MigrationSession *expected);

private:
    SessionManager() = default;

    ~SessionManager() = default;

    std::mutex mtx_;

    std::unordered_map<std::string, std::shared_ptr<MigrationSession>> sessions_;
};

struct EXchangePkAndReport {
    std::string domainName;
    std::string uuid;
    std::string cert;
    std::string pubKey;
    std::string hostReport;
    std::string vmReport;
};

} // namespace virtrust
