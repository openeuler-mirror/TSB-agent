/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_service_impl.h"

#include <memory>
#include <exception>
#include <regex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "libvirtrustd/defines.h"
#include "tsb_agent/tsb_agent.h"

#include "virtrust/api/domain.h"
#include "virtrust/base/logger.h"
#include "virtrust/base/node_admission.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
const std::regex IP_REGEX(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");

namespace {
std::string ExtractSingleIP(const std::string &str)
{
    std::vector<std::string> ips;
    std::sregex_iterator it(str.begin(), str.end(), IP_REGEX);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        ips.push_back((*it)[1]);
    }

    if (ips.empty()) {
        VIRTRUST_LOG_ERROR("|ExtracSingleIP|END|returnF|No IP address found");
        return "";
    } else if (ips.size() > 1) {
        VIRTRUST_LOG_ERROR("|ExtracSingleIP|END|returnF|IP address is not in one or more");
        return "";
    }
    return ips[0];
}

// API 的查询只用于构造请求；守护进程取得独占资格后再次核验，避免等待 UDS 时虚机已变化。
bool CheckSourceDomain(const protos::DomainMigraterRequest &request)
{
    auto conn = std::make_unique<ConnCtx>();
    if (!conn->SetUri(request.localuri()) || !conn->Connect()) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Failed to connect to source URI: {}", request.localuri());
        return false;
    }
    std::unordered_map<std::string, DomainInfo> domains;
    if (DomainList(conn, LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE, domains, false) != VirtrustRc::OK) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Failed to list source domains");
        return false;
    }
    const auto it = domains.find(request.uuid());
    if (it == domains.end() || it->second.domainName != request.domainname() ||
        it->second.state != VIR_DOMAIN_SHUTOFF) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|Precheck|Source domain changed: name={}, uuid={}",
                           request.domainname(), request.uuid());
        return false;
    }
    return true;
}

// Cleanup 异常时至少撤销 manager 中的会话登记，避免释放节点资格后仍残留同 UUID 会话。
void CleanupSourceSessionNoThrow(const std::shared_ptr<MigrationSession> &session, const std::string &uuid) noexcept
{
    if (!session) {
        return;
    }
    try {
        session->Cleanup();
    } catch (...) {
        try {
            SessionManager::GetInstance().RemoveSession(uuid);
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
            response->set_result(static_cast<uint32_t>(outcome == LockOutcome::Busy ? VirtrustRc::BUSY
                                                                                    : VirtrustRc::ERROR));
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
            return grpc::Status::OK;
        }
        if (session->OnMigrateRequestReceived() != MigrateSessionRc::OK) {
            // 预检查失败是终态；不能让无定时器的 Failed 会话永久持有节点资格。
            session->Cleanup();
            return grpc::Status::OK;
        }
        response->set_result(static_cast<uint32_t>(VirtrustRc::OK));
        return grpc::Status::OK;
    } catch (const std::exception &error) {
        CleanupResponderSessionNoThrow(session);
        try {
            VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|Exception: {}", error.what());
        } catch (...) {
        }
        return grpc::Status::OK;
    } catch (...) {
        CleanupResponderSessionNoThrow(session);
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
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = RunResponderStep(session, "ExchangePkAndReport", [&] {
        VIRTRUST_LOG_DEBUG("|ExchangePkAndReport|START||start handle rpc request");
        return session->OnExchangeKeyRequestReceived(request, response);
    });
    if (rc != MigrateSessionRc::OK) {
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
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = RunResponderStep(session, "StartMigration", [&] {
        VIRTRUST_LOG_DEBUG("|StartMigration|START||start handle rpc request");
        return session->OnStartMigrationRequestReceived();
    });
    if (rc != MigrateSessionRc::OK) {
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
        response->set_result(1);
        return grpc::Status::OK;
    }
    // 服务端
    int32_t result = 0;
    MigrateSessionRc rc = RunResponderStep(session, "SendVRsourceData", [&] {
        VIRTRUST_LOG_DEBUG("|SendVRsourceData|START||start handle rpc request");
        return session->OnTransferDataRequestReceived(request, result);
    });
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        if (result != 0) {
            response->set_result(result);
        }
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
        response->set_result(1);
        return grpc::Status::OK;
    }
    MigrateSessionRc rc = RunResponderStep(session, "NotifyVRMigrateResult", [&] {
        VIRTRUST_LOG_DEBUG("|NotifyVRMigrateResult|START||start handle rpc request");
        return session->OnFinishedRequestReceived(request->result() == 0);
    });
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        return grpc::Status::OK;
    }
    response->set_result(0);
    return grpc::Status::OK;
}

// 6: 发起迁移任务, virsh-sh主动这个方法
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
    try {
        VIRTRUST_LOG_DEBUG("|DomainMigrate|START||start handle uds request");
        // 独立校验 UDS 输入，防止调用方绕过 API 让本节点锁保护远端 libvirt 操作。
        if (!IsLocalMigrationSourceUri(request->localuri())) {
            VIRTRUST_LOG_ERROR("|DomainMigrate|SourceUri|Unsupported migration source URI: {}", request->localuri());
            return grpc::Status::OK;
        }
        const std::string destIp = ExtractSingleIP(request->desturi());
        if (destIp.empty()) {
            VIRTRUST_LOG_ERROR("|MigrationServiceImpl DomainMigrate|END|returnF|invalid ip, destUri is: {}",
                               request->desturi());
            return grpc::Status::OK;
        }

        // 令牌由当前守护进程请求持有，直至源端状态机和 Cleanup 全部返回；不从 API 转移描述符。
        const auto outcome = admission.TryAcquire(AdmissionKind::Migration);
        if (outcome != LockOutcome::Acquired) {
            response->set_result(static_cast<uint32_t>(outcome == LockOutcome::Busy ? VirtrustRc::BUSY
                                                                                    : VirtrustRc::ERROR));
            // 诊断失败不能把已经确定的 Busy 改写为通用 Error。
            try {
                VIRTRUST_LOG_ERROR("|DomainMigrate|Admission|{}", admission.LastError());
            } catch (...) {
            }
            return grpc::Status::OK;
        }
        if (!CheckSourceDomain(*request)) {
            return grpc::Status::OK;
        }

        LinkConfig config = ConfigMgr::Instance().GetLinkConfig();
        config.ip = destIp;
        auto &mgr = SessionManager::GetInstance();
        // 源端整个迁移过程始终由外层请求持锁admission；session 无须再获取同一节点的锁
        session = mgr.CreateSession(MigrationSession::Role::Initiator, request->uuid(), request->domainname(),
                                    request->desturi(), request->localuri(), request->flags());
        if (!session) {
            VIRTRUST_LOG_ERROR("|DomainMigrate|Session|Failed to create source session: uuid={}", request->uuid());
            return grpc::Status::OK;
        }
        // 源端会话同步运行；先清理会话，再由 admission 析构释放独占资格。
        session->SetRpcClient(std::make_unique<RpcClient>(config));
        const auto result = session->Start();
        session->Cleanup();
        session.reset();
        if (result != MigrateSessionRc::OK) {
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
        CleanupSourceSessionNoThrow(session, request->uuid());
        response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
        try {
            VIRTRUST_LOG_ERROR("|DomainMigrate|Exception|{}", error.what());
        } catch (...) {
        }
    } catch (...) {
        CleanupSourceSessionNoThrow(session, request->uuid());
        response->set_result(static_cast<uint32_t>(VirtrustRc::ERROR));
        try {
            VIRTRUST_LOG_ERROR("|DomainMigrate|Exception|Unknown source migration failure");
        } catch (...) {
        }
    }
    return grpc::Status::OK;
}

} // namespace virtrust
