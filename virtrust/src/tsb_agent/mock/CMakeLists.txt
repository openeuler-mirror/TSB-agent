# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

# Mock TSB Agent 编译为共享库 libinterfac.so
# 使用方式: 将编译出的 libinterfac.so 部署到系统，代替真实的 libinterfac.so 用于测试

# SO 导出层 + mock 实现
add_library(interfac SHARED ${CMAKE_CURRENT_LIST_DIR}/tsb_agent_adaptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tsb_agent_impl.cpp)

set_target_properties(interfac PROPERTIES
        VERSION 1.0.0
        SOVERSION 1
        OUTPUT_NAME interfac
        POSITION_INDEPENDENT_CODE ON
)

target_include_directories(interfac PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(interfac PRIVATE Deps::spdlog Deps::secure_c)

# 安装配置: 安装到 lib 目录
install(TARGETS interfac
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT runtime)
