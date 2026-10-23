/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <string>

#include "gtest/gtest.h"

#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_client.h"

namespace virtrust {

class GrpcClientTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize test configuration
        linkConfig_.caPath = "/test/ca.pem";
        linkConfig_.certPath = "/test/cert.pem";
        linkConfig_.skPath = "/test/sk.pem";
        linkConfig_.ip = "127.0.0.1";
        linkConfig_.ipMask = "127.0.0.0/24";
        linkConfig_.port = 50051;
        linkConfig_.udsPath = "/tmp/test.sock";

        migrationConfig_.domainName = "test-domain-1";
        migrationConfig_.uuid = "12345678-1234-1234-1234-123456789001";
        migrationConfig_.destUri = "qemu+tcp://dest-host/system";
        migrationConfig_.localUri = "qemu+tcp://src-host/system";
        migrationConfig_.flags = 0;
    }

    LinkConfig linkConfig_;
    MigrationConfig migrationConfig_;
};

TEST_F(GrpcClientTest, UdsClientConstructor)
{
    // Test that UdsClient can be constructed with valid config
    UdsClient client(linkConfig_);

    // The constructor should not throw, and the client should be valid
    // Since we can't directly access private members, we just ensure construction succeeds
    SUCCEED();
}

TEST_F(GrpcClientTest, UdsClientConstructorWithEmptyConfig)
{
    // Test with empty config
    LinkConfig emptyConfig;
    UdsClient client(emptyConfig);

    // Should still construct successfully
    SUCCEED();
}

TEST_F(GrpcClientTest, UdsClientDomainMigrateRequest)
{
    UdsClient client(linkConfig_);

    const auto result = client.DomainMigrate(migrationConfig_);

    // Should return 0 when mock server and vm is valid
    EXPECT_EQ(result.rc, VirtrustRc::OK);
}

TEST_F(GrpcClientTest, UdsClientDomainMigrateWithEmptyConfig)
{
    UdsClient client(linkConfig_);

    MigrationConfig emptyConfig;
    const auto result = client.DomainMigrate(emptyConfig);

    // Should return error 1 when server emptyConfig
    EXPECT_EQ(result.rc, VirtrustRc::ERROR);
}

TEST_F(GrpcClientTest, RpcClientConstructor)
{
    // Test that RpcClient can be constructed with valid config
    RpcClient client(linkConfig_);

    // The constructor should not throw, and the client should be valid
    SUCCEED();
}

TEST_F(GrpcClientTest, RpcClientConstructorWithEmptyConfig)
{
    // Test with empty config
    LinkConfig emptyConfig;
    RpcClient client(emptyConfig);

    // Should still construct successfully
    SUCCEED();
}

TEST_F(GrpcClientTest, RpcClientPrepareMigration)
{
    RpcClient client(linkConfig_);

    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;

    // Set up a basic request
    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // This will fail because there's no server running, but we can test the request construction
    // and error handling
    int32_t result = client.PrepareMigration(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, MockPrepareSuccessDoesNotCarryHiddenFailureDiagnostic)
{
    RpcClient client(linkConfig_);
    protos::PrepareMigRequest request;
    request.set_uuid("test-uuid");
    request.set_domainname("test-domain");
    protos::PrepareMigReply first;
    protos::PrepareMigReply second;

    ASSERT_EQ(client.PrepareMigration(5, request, &first), 0);
    ASSERT_EQ(client.PrepareMigration(5, request, &second), 0);
    // 模拟远端成功时不能先执行本地真实服务、再覆盖其失败 result。
    EXPECT_FALSE(first.has_diagnostic());
    EXPECT_FALSE(second.has_diagnostic());
}

TEST_F(GrpcClientTest, RpcClientExchangePkAndReport)
{
    RpcClient client(linkConfig_);

    protos::EXchangePkAndReportRequest request;
    protos::EXchangePkAndReportReply response;

    // Set up a basic request
    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");
    request.set_cert("test-certificate");
    request.set_publickey("test-public-key");
    // Note: hostReport and vmReport are TrustReportNew messages, not strings
    // For test purposes, we'll leave them unset

    // This will fail because there's no server running, but we can test the request construction
    // and error handling
    int32_t result = client.ExchangePkAndReport(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientStartMigration)
{
    RpcClient client(linkConfig_);

    protos::StartMigRequest request;
    protos::StartMigReply response;

    // Set up a basic request
    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // This will fail because there's no server running, but we can test the request construction
    // and error handling
    int32_t result = client.StartMigration(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientSendVRsourceData)
{
    RpcClient client(linkConfig_);

    protos::VRsourceInfoRequest request;
    protos::VRsourceInfoReply response;

    // Set up a basic request
    request.set_uuid("test-uuid");
    request.set_cipherdata("test-vr-data");

    // This will fail because there's no server running, but we can test the request construction
    // and error handling
    int32_t result = client.SendVRsourceData(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientNotifyVRMigrateResult)
{
    RpcClient client(linkConfig_);

    protos::MigrateResultRequest request;
    protos::MigrateResultReply response;

    // Set up a basic request
    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");
    request.set_result(1); // 1 for success

    // This will fail because there's no server running, but we can test the request construction
    // and error handling
    int32_t result = client.NotifyVRMigrateResult(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientWithTimeout)
{
    RpcClient client(linkConfig_);

    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;

    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // Test with very short timeout (1 second) - should still handle gracefully
    int32_t result = client.PrepareMigration(1, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientWithZeroTimeout)
{
    RpcClient client(linkConfig_);

    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;

    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // Test with zero timeout - should still handle gracefully
    int32_t result = client.PrepareMigration(0, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientWithInvalidIp)
{
    LinkConfig invalidConfig = linkConfig_;
    invalidConfig.ip = "invalid.ip.address";

    RpcClient client(invalidConfig);

    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;

    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // Should handle invalid IP gracefully
    int32_t result = client.PrepareMigration(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, RpcClientWithInvalidPort)
{
    LinkConfig invalidConfig = linkConfig_;
    invalidConfig.port = 0; // Invalid port

    RpcClient client(invalidConfig);

    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;

    request.set_domainname("test-domain");
    request.set_uuid("test-uuid");

    // Should handle invalid port gracefully
    int32_t result = client.PrepareMigration(5, request, &response);

    // Should return 0 when mock server
    EXPECT_EQ(result, 0);
}

TEST_F(GrpcClientTest, UdsClientWithInvalidUdsPath)
{
    LinkConfig invalidConfig = linkConfig_;
    invalidConfig.udsPath = ""; // Empty UDS path

    UdsClient client(invalidConfig);

    // Should handle empty UDS path gracefully
    const auto result = client.DomainMigrate(migrationConfig_);

    // Should return 0 when mock server and vm is valid
    EXPECT_EQ(result.rc, VirtrustRc::OK);
}

} // namespace virtrust
