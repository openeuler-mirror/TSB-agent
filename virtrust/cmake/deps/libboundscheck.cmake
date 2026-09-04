# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# libboundscheck is provided by the system package (yum: libboundscheck).
# NOTE the base package already ships headers and the shared library.
find_path(BOUNDSCHECK_INCLUDE_DIR securec.h
          DOC "System libboundscheck headers (package: libboundscheck)")
find_library(BOUNDSCHECK_LIBRARY boundscheck
             DOC "System libboundscheck library (package: libboundscheck)")
if(NOT BOUNDSCHECK_INCLUDE_DIR OR NOT BOUNDSCHECK_LIBRARY)
  message(
    FATAL_ERROR "libboundscheck not found, please install libboundscheck first")
endif()
message(
  STATUS
    "Using system libboundscheck: headers=${BOUNDSCHECK_INCLUDE_DIR} lib=${BOUNDSCHECK_LIBRARY}")

add_library(libboundscheck-itf INTERFACE)
target_include_directories(libboundscheck-itf INTERFACE ${BOUNDSCHECK_INCLUDE_DIR})
target_link_libraries(libboundscheck-itf INTERFACE ${BOUNDSCHECK_LIBRARY})

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::secure_c ALIAS libboundscheck-itf)
