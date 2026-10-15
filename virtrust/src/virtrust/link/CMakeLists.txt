# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${PROTO_SRC}
    ${CMAKE_CURRENT_LIST_DIR}/grpc_server.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_service_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_session.cpp)

# 在模糊测试模式下添加模拟实现源文件。
if(ENABLE_MOCK_4_FUZZ)
  list(APPEND VIRTRUST_SOURCE_FILES
       ${CMAKE_CURRENT_SOURCE_DIR}/mock/grpc_client_mock.cpp)
else()
  list(APPEND VIRTRUST_SOURCE_FILES
       ${CMAKE_CURRENT_LIST_DIR}/grpc_client.cpp)
endif()

set(VIRTRUST_PROTO_SOURCE_FILES ${VIRTRUST_PROTO_SOURCE_FILES}
                              ${CMAKE_CURRENT_LIST_DIR}/proto/migrate.proto)

# 添加通信目录的测试。
add_virtrust_test_if(proto_tools_test)
if(BUILD_TEST)
  target_link_libraries(proto_tools_test PRIVATE virtrust_proto Deps::secure_c)
endif()
add_virtrust_test_if(grpc_client_test)
if(BUILD_TEST)
  target_link_libraries(grpc_client_test PRIVATE virtrust_proto Deps::secure_c)
endif()
add_virtrust_test_if(grpc_server_test)
add_virtrust_test_if(grpc_server_fault_test)
if(BUILD_TEST)
  set_tests_properties(grpc_server_test grpc_server_fault_test PROPERTIES TIMEOUT 30)
  # 测试直接调用 gRPC 头文件接口，须显式链接其内联实现使用的底层库。
  target_link_libraries(grpc_server_fault_test PRIVATE grpc++ grpc gpr)
  target_compile_definitions(grpc_server_test PRIVATE
    VIRTRUST_TEST_CERT_DIR="${VIRTRUST_TEST_CERT_DIR}")
endif()
# add_virtrust_test_if(migration_session_test ${BUILD_TEST}) if(BUILD_TEST)
# target_link_libraries(migration_session_test PRIVATE virtrust_proto) endif()
# add_virtrust_test_if(migration_service_impl_test ${BUILD_TEST}) if(BUILD_TEST)
# target_link_libraries(migration_service_impl_test PRIVATE virtrust_proto)
# endif()

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

set(VIRTRUST_PROTO_SOURCE_FILES
    ${VIRTRUST_PROTO_SOURCE_FILES}
    PARENT_SCOPE)
