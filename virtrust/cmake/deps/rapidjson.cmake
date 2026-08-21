# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# rapidjson is a header-only lib, use the system package (yum: rapidjson-devel)
find_path(RAPIDJSON_INCLUDE_DIR rapidjson/document.h
          DOC "System rapidjson headers (package: rapidjson-devel)")
if(NOT RAPIDJSON_INCLUDE_DIR)
  message(
    FATAL_ERROR
      "rapidjson headers not found, please install rapidjson-devel first")
endif()
message(STATUS "Using system rapidjson headers: ${RAPIDJSON_INCLUDE_DIR}")

add_library(librapidjson INTERFACE)
target_include_directories(librapidjson INTERFACE ${RAPIDJSON_INCLUDE_DIR})

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::rapidjson ALIAS librapidjson)
