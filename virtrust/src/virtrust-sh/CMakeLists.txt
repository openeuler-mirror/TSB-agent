# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

add_library(virtrust-sh-obj OBJECT)

set(VIRTRUST_SH_SOURCE_FILES "")

add_subdirectory(operator)

target_sources(virtrust-sh-obj PRIVATE ${VIRTRUST_SH_SOURCE_FILES})

target_include_directories(
  virtrust-sh-obj PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                          ${CMAKE_DEPS_INCLUDEDIR})

target_link_libraries(virtrust-sh-obj PRIVATE virtrust-shared)

# ----------------
# Final Executable
# ----------------

add_executable(virtrust-sh ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(
  virtrust-sh PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                      ${CMAKE_DEPS_INCLUDEDIR})

target_link_libraries(virtrust-sh PRIVATE virtrust-sh-obj virtrust-shared
                                      Deps::spdlog)

if(BUILD_TEST AND ENABLE_MOCK_4_FUZZ)
  add_virtrust_sh_test_if(cli_busy_test)
  target_link_libraries(cli_busy_test PRIVATE domain-admission-test-obj Deps::secure_c)
  target_include_directories(cli_busy_test PRIVATE ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/virtrust)
  target_link_options(cli_busy_test PRIVATE ${VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS})
  set_tests_properties(cli_busy_test PROPERTIES TIMEOUT 15)
endif()
