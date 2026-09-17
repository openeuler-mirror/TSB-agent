# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES ${VIRTRUST_SOURCE_FILES})

# Add Mock source files in Fuzz mode
if(ENABLE_MOCK_4_FUZZ)
    list(APPEND VIRTRUST_SOURCE_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/mock/libvirt_mock.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/mock/libguestfs_mock.cpp
    )
endif()

add_virtrust_test_if(libxml2_test)

# HACK libguestfs has memory leaks, so we disable this test under asan
#
if(NOT CMAKE_BUILD_TYPE STREQUAL "Asan")
  add_virtrust_test_if(libguestfs_test)
endif()

add_virtrust_test_if(libvirt_test)
add_virtrust_test_if(openssl_test)
add_virtrust_test_if(dllib_test)

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
