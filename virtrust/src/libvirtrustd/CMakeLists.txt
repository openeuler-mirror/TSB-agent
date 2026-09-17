# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# object lib: business logic (testable via add_libvirtrustd_test_if)
add_library(libvirtrustd-obj OBJECT)
target_sources(libvirtrustd-obj PRIVATE ${CMAKE_CURRENT_LIST_DIR}/utils.cpp)

target_include_directories(
  libvirtrustd-obj PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                          $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(libvirtrustd-obj PRIVATE virtrust-shared Deps::rapidjson
                                                Deps::spdlog)

# executable
add_executable(libvirtrustd ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(
  libvirtrustd PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                       $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(libvirtrustd PRIVATE libvirtrustd-obj virtrust-shared
                                              Deps::rapidjson Deps::spdlog)
