# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# spdlog is provided by the system package (yum: spdlog-devel).
# NOTE openEuler spdlog is built with external fmt (SPDLOG_FMT_EXTERNAL), so
# fmt is required as well (yum: fmt-devel) and the bundled fmt headers
# (spdlog/fmt/bundled/*) are not available.
find_path(SPDLOG_INCLUDE_DIR spdlog/spdlog.h
          DOC "System spdlog headers (package: spdlog-devel)")
find_library(SPDLOG_LIBRARY spdlog
             DOC "System spdlog library (package: spdlog-devel)")
find_library(FMT_LIBRARY fmt
             DOC "System fmt library (package: fmt-devel)")
if(NOT SPDLOG_INCLUDE_DIR OR NOT SPDLOG_LIBRARY OR NOT FMT_LIBRARY)
  message(
    FATAL_ERROR "spdlog/fmt not found, please install spdlog-devel and fmt-devel")
endif()
message(
  STATUS
    "Using system spdlog: headers=${SPDLOG_INCLUDE_DIR} lib=${SPDLOG_LIBRARY} fmt=${FMT_LIBRARY}")

add_library(libspdlog INTERFACE)
target_include_directories(libspdlog INTERFACE ${SPDLOG_INCLUDE_DIR})
target_link_libraries(libspdlog INTERFACE ${SPDLOG_LIBRARY} ${FMT_LIBRARY})
# match the flags pkg-config spdlog provides for the external-fmt build
target_compile_definitions(
  libspdlog INTERFACE SPDLOG_FMT_EXTERNAL SPDLOG_COMPILED_LIB SPDLOG_SHARED_LIB)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::spdlog ALIAS libspdlog)
