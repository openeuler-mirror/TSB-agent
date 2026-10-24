/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include <atomic>
#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "virtrust/link/grpc_client.h"

namespace virtrust {
namespace {

class RetryService final : public protos::MigrationService::Service {
public:
    std::atomic<int> calls{0};
    grpc::StatusCode firstStatus = grpc::StatusCode::UNAVAILABLE;
    uint32_t businessResult = 0;
    bool alwaysUnavailable = false;
    int inProgressResponsesRemaining = 0;
    bool alwaysInProgressAfterFirst = false;
    std::chrono::milliseconds firstDelay{0};
    std::atomic<int> exchangeCalls{0};
    std::atomic<int> startCalls{0};
    std::atomic<int> transferCalls{0};
    std::atomic<int> finishCalls{0};
    std::array<std::string, 2> exchangeRequests;
    std::array<std::string, 2> startRequests;
    std::array<std::string, 2> transferRequests;
    std::array<std::string, 2> finishRequests;
    std::string firstRequest;
    std::string secondRequest;

    grpc::Status PrepareMigration(grpc::ServerContext *, const protos::PrepareMigRequest *request,
                                  protos::PrepareMigReply *response) override
    {
        const int call = ++calls;
        if (call == 1 && firstDelay.count() != 0) {
            std::this_thread::sleep_for(firstDelay);
        }
        if (call == 1) {
            request->SerializeToString(&firstRequest);
        } else if (call == 2) {
            request->SerializeToString(&secondRequest);
        }
        response->set_result(businessResult);
        if (call > 1 && (inProgressResponsesRemaining > 0 || alwaysInProgressAfterFirst)) {
            if (inProgressResponsesRemaining > 0) {
                --inProgressResponsesRemaining;
            }
            return {grpc::StatusCode::UNAVAILABLE, "Migration step is already in progress",
                    "virtrust.migration.step-in-progress"};
        }
        if ((call == 1 || alwaysUnavailable) && firstStatus != grpc::StatusCode::OK) {
            return {firstStatus, "injected first-call failure"};
        }
        return grpc::Status::OK;
    }

    template <typename Request, typename Reply>
    grpc::Status ReplyAfterTransient(std::atomic<int> &counter, std::array<std::string, 2> &requests,
                                     const Request *request, Reply *response)
    {
        const int call = ++counter;
        if (call <= 2) {
            request->SerializeToString(&requests[static_cast<size_t>(call - 1)]);
        }
        response->set_result(0);
        return call == 1 ? grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected transient failure") :
                           grpc::Status::OK;
    }

    grpc::Status ExchangePkAndReport(grpc::ServerContext *, const protos::EXchangePkAndReportRequest *request,
                                     protos::EXchangePkAndReportReply *response) override
    {
        return ReplyAfterTransient(exchangeCalls, exchangeRequests, request, response);
    }

    grpc::Status StartMigration(grpc::ServerContext *, const protos::StartMigRequest *request,
                                protos::StartMigReply *response) override
    {
        return ReplyAfterTransient(startCalls, startRequests, request, response);
    }

    grpc::Status SendVRsourceData(grpc::ServerContext *, const protos::VRsourceInfoRequest *request,
                                  protos::VRsourceInfoReply *response) override
    {
        return ReplyAfterTransient(transferCalls, transferRequests, request, response);
    }

    grpc::Status NotifyVRMigrateResult(grpc::ServerContext *, const protos::MigrateResultRequest *request,
                                       protos::MigrateResultReply *response) override
    {
        return ReplyAfterTransient(finishCalls, finishRequests, request, response);
    }
};

class RpcClientRetryTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&service_);
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(port, 0);
        config_.ip = "127.0.0.1";
        config_.port = static_cast<uint16_t>(port);
        config_.rpcRetryMaxAttempts = 3;
        config_.rpcRetryInitialBackoffMs = 1;
        config_.rpcRetryMaxBackoffMs = 1;
    }

    void TearDown() override
    {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    protos::PrepareMigRequest Request() const
    {
        protos::PrepareMigRequest request;
        request.set_uuid("12345678-1234-1234-1234-123456789001");
        request.set_attempt_id("0123456789abcdef0123456789abcdef");
        request.set_domainname("retry-test");
        return request;
    }

    RetryService service_;
    LinkConfig config_;
    std::unique_ptr<grpc::Server> server_;
};

TEST_F(RpcClientRetryTest, UnavailableRetriesSameRequestAndGetsBusinessReply)
{
    RpcClient client(config_);
    const auto request = Request();
    protos::PrepareMigReply reply;
    ASSERT_EQ(client.PrepareMigration(2, request, &reply), 0);
    EXPECT_EQ(service_.calls, 2);
    EXPECT_FALSE(service_.firstRequest.empty());
    EXPECT_EQ(service_.firstRequest, service_.secondRequest);
    EXPECT_EQ(reply.result(), 0U);
}

TEST_F(RpcClientRetryTest, BusinessFailureIsNotRetried)
{
    service_.firstStatus = grpc::StatusCode::OK;
    service_.businessResult = 1;
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    EXPECT_EQ(client.PrepareMigration(2, Request(), &reply), 1);
    EXPECT_EQ(service_.calls, 1);
}

TEST_F(RpcClientRetryTest, UnreplayableStepIsNotRetried)
{
    service_.firstStatus = grpc::StatusCode::ABORTED;
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    EXPECT_EQ(client.PrepareMigration(2, Request(), &reply), RPC_TRANSPORT_FAILURE);
    EXPECT_EQ(service_.calls, 1);
}

TEST_F(RpcClientRetryTest, RepeatedUnavailableStopsAtConfiguredAttemptLimit)
{
    service_.alwaysUnavailable = true;
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    EXPECT_EQ(client.PrepareMigration(2, Request(), &reply), RPC_TRANSPORT_FAILURE);
    EXPECT_EQ(service_.calls, 3);
}

TEST_F(RpcClientRetryTest, InProgressResponsesUseStageDeadlineInsteadOfNetworkAttemptLimit)
{
    // 首次网络失败后，目的端原请求继续处理；三个“处理中”回复不应提前耗尽网络重试配额。
    service_.inProgressResponsesRemaining = 3;
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    EXPECT_EQ(client.PrepareMigration(2, Request(), &reply), 0);
    EXPECT_EQ(service_.calls, 5);
}

TEST_F(RpcClientRetryTest, InProgressPollingStopsAtStageDeadline)
{
    service_.alwaysInProgressAfterFirst = true;
    config_.rpcRetryInitialBackoffMs = 100;
    config_.rpcRetryMaxBackoffMs = 100;
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    const auto begin = std::chrono::steady_clock::now();
    EXPECT_EQ(client.PrepareMigration(1, Request(), &reply), RPC_TRANSPORT_FAILURE);
    EXPECT_LT(std::chrono::steady_clock::now() - begin, std::chrono::milliseconds(1600));
    EXPECT_GT(service_.calls, 3);
}

TEST_F(RpcClientRetryTest, AllOtherPeerMethodsUseSameStageRetryRule)
{
    RpcClient client(config_);
    protos::EXchangePkAndReportRequest exchange;
    protos::EXchangePkAndReportReply exchangeReply;
    exchange.set_attempt_id(Request().attempt_id());
    ASSERT_EQ(client.ExchangePkAndReport(2, exchange, &exchangeReply), 0);
    EXPECT_EQ(service_.exchangeCalls, 2);
    EXPECT_FALSE(service_.exchangeRequests[0].empty());
    EXPECT_EQ(service_.exchangeRequests[0], service_.exchangeRequests[1]);

    protos::StartMigRequest start;
    protos::StartMigReply startReply;
    start.set_attempt_id(Request().attempt_id());
    ASSERT_EQ(client.StartMigration(2, start, &startReply), 0);
    EXPECT_EQ(service_.startCalls, 2);
    EXPECT_FALSE(service_.startRequests[0].empty());
    EXPECT_EQ(service_.startRequests[0], service_.startRequests[1]);

    protos::VRsourceInfoRequest transfer;
    protos::VRsourceInfoReply transferReply;
    transfer.set_attempt_id(Request().attempt_id());
    ASSERT_EQ(client.SendVRsourceData(2, transfer, &transferReply), 0);
    EXPECT_EQ(service_.transferCalls, 2);
    EXPECT_FALSE(service_.transferRequests[0].empty());
    EXPECT_EQ(service_.transferRequests[0], service_.transferRequests[1]);

    protos::MigrateResultRequest finish;
    protos::MigrateResultReply finishReply;
    finish.set_attempt_id(Request().attempt_id());
    ASSERT_EQ(client.NotifyVRMigrateResult(2, finish, &finishReply), 0);
    EXPECT_EQ(service_.finishCalls, 2);
    EXPECT_FALSE(service_.finishRequests[0].empty());
    EXPECT_EQ(service_.finishRequests[0], service_.finishRequests[1]);
}

TEST_F(RpcClientRetryTest, StageDeadlineIsNotMultipliedByAttemptCount)
{
    service_.firstDelay = std::chrono::milliseconds(1200);
    RpcClient client(config_);
    protos::PrepareMigReply reply;
    const auto begin = std::chrono::steady_clock::now();
    EXPECT_EQ(client.PrepareMigration(1, Request(), &reply), RPC_TRANSPORT_FAILURE);
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    EXPECT_LT(elapsed, std::chrono::milliseconds(1600));
    EXPECT_EQ(service_.calls, 1);
}

} // namespace
} // namespace virtrust
