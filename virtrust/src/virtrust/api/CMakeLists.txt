# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTURST_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/context.cpp
    ${CMAKE_CURRENT_LIST_DIR}/domain.cpp
    ${CMAKE_CURRENT_LIST_DIR}/create_connection_args.cpp)

add_virtrust_test_if(domain_test)

if(BUILD_TEST AND ENABLE_MOCK_4_FUZZ)
  # 测试对象独立编译，链接包装只存在于测试程序，不改变生产共享库。
  add_library(domain-admission-test-obj OBJECT domain.cpp admission_test_support.cpp)
  target_include_directories(domain-admission-test-obj PRIVATE
    ${PROJECT_SOURCE_DIR}/src ${CMAKE_DEPS_INCLUDEDIR} ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/virtrust)
  target_link_libraries(domain-admission-test-obj PRIVATE virtrust-shared Deps::gtest Deps::secure_c)
  target_compile_definitions(domain-admission-test-obj PRIVATE VIRTRUST_REAL_FILE_LOCK_TEST)
  set(VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS
    "LINKER:--wrap=_ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj"
    "LINKER:--wrap=open" "LINKER:--wrap=GetVRoots" "LINKER:--wrap=StartVRoot"
    "LINKER:--wrap=StopVRoot" "LINKER:--wrap=RemoveVRoot" CACHE INTERNAL "Task 4 test wrappers")
  target_link_libraries(domain_test PRIVATE domain-admission-test-obj)
  target_link_options(domain_test PRIVATE ${VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS})
  set_tests_properties(domain_test PROPERTIES TIMEOUT 30)
endif()

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/context.h ${CMAKE_CURRENT_LIST_DIR}/domain.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/virtrust/api/
  PERMISSIONS OWNER_READ)
