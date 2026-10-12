# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# 业务逻辑对象库，可通过 add_libvirtrustd_test_if 注册测试。
add_library(libvirtrustd-obj OBJECT)
target_sources(libvirtrustd-obj PRIVATE ${CMAKE_CURRENT_LIST_DIR}/utils.cpp)
target_sources(libvirtrustd-obj PRIVATE ${CMAKE_CURRENT_LIST_DIR}/daemon_instance.cpp)

target_include_directories(
  libvirtrustd-obj PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                         $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(libvirtrustd-obj PRIVATE virtrust-shared Deps::rapidjson
                                            Deps::spdlog)

# 守护进程可执行程序。
add_executable(libvirtrustd ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(
  libvirtrustd PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                     $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(libvirtrustd PRIVATE libvirtrustd-obj virtrust-shared
                                         Deps::rapidjson Deps::spdlog)

add_libvirtrustd_test_if(utils_test)
add_libvirtrustd_test_if(daemon_instance_test)
if(BUILD_TEST)
  # 测试回调直接调用 Shutdown 等接口，不依赖业务共享库的私有传递依赖。
  target_link_libraries(daemon_instance_test PRIVATE grpc++ grpc gpr)
  set_tests_properties(daemon_instance_test PROPERTIES TIMEOUT 15)
endif()
