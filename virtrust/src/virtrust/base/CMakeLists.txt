# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/process_file_lock.cpp
    ${CMAKE_CURRENT_LIST_DIR}/custom_logger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log_adapt.cpp
    ${CMAKE_CURRENT_LIST_DIR}/str_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/exception.cpp)

add_virtrust_test_if(exception_test)
add_virtrust_test_if(custom_logger_test)
add_virtrust_test_if(log_adapt_test)
add_virtrust_test_if(str_utils_test)
# 真实文件锁测试在 mock 构建中也运行，避免互斥能力被模拟实现绕过。
add_virtrust_test_if(process_file_lock_test)
if(BUILD_TEST)
  # 为包含 fork 和阻塞加锁的用例设置整体超时，防止回归时无限挂起。
  set_tests_properties(process_file_lock_test PROPERTIES TIMEOUT 15)
endif()

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/custom_logger.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/virtrust/base
  PERMISSIONS OWNER_READ)

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
