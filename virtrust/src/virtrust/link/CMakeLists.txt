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
if(BUILD_TEST AND ENABLE_MOCK_4_FUZZ)
  # 服务入口单独编译，使链接包装仅影响定向测试，不改变生产共享库。
  add_library(source-migration-admission-test-obj OBJECT migration_service_impl.cpp)
  target_include_directories(source-migration-admission-test-obj PRIVATE
    ${PROJECT_SOURCE_DIR}/src ${CMAKE_DEPS_INCLUDEDIR} ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/virtrust)
  target_link_libraries(source-migration-admission-test-obj PRIVATE virtrust-shared Deps::gtest Deps::secure_c)
  add_virtrust_test_if(source_migration_admission_test)
  target_link_libraries(source_migration_admission_test PRIVATE
    source-migration-admission-test-obj grpc++ grpc gpr protobuf)
  target_link_options(source_migration_admission_test PRIVATE
    "LINKER:--wrap=_ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj"
    "LINKER:--wrap=_ZN8virtrust16MigrationSession5StartEv"
    "LINKER:--wrap=_ZN8virtrust16MigrationSession7CleanupEv")
  set_tests_properties(source_migration_admission_test PROPERTIES TIMEOUT 30)
endif()
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
