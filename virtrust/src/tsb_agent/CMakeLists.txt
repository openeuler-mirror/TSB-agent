# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

# mock
add_subdirectory(mock)

add_library(tsb-agent STATIC tsb_agent_adaptor.cpp)
set_target_properties(tsb-agent PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(tsb-agent PRIVATE dl)
target_include_directories(
  tsb-agent PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
