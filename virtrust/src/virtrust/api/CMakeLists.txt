# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTURST_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/context.cpp
    ${CMAKE_CURRENT_LIST_DIR}/domain.cpp
    ${CMAKE_CURRENT_LIST_DIR}/create_connection_args.cpp)

add_virtrust_test_if(domain_test)
add_virtrust_test_if(create_connection_args_test)

if(BUILD_TEST AND ENABLE_MOCK_4_FUZZ)
  # 测试对象独立编译，链接包装只存在于测试程序，不改变生产共享库。
  add_library(domain-admission-test-obj OBJECT domain.cpp admission_test_support.cpp)
  target_include_directories(domain-admission-test-obj PRIVATE
    ${PROJECT_SOURCE_DIR}/src ${CMAKE_DEPS_INCLUDEDIR} ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/virtrust)
  target_link_libraries(domain-admission-test-obj PRIVATE virtrust-shared Deps::gtest Deps::secure_c)
  target_compile_definitions(domain-admission-test-obj PRIVATE VIRTRUST_REAL_FILE_LOCK_TEST)
  add_virtrust_test_if(domain_admission_test)
  set(VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS
    "LINKER:--wrap=_ZN8virtrust13NodeAdmission10TryAcquireENS_13AdmissionKindERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEj"
    "LINKER:--wrap=open" "LINKER:--wrap=GetVRoots" "LINKER:--wrap=StartVRoot"
    "LINKER:--wrap=StopVRoot" "LINKER:--wrap=RemoveVRoot" CACHE INTERNAL "Task 4 test wrappers")
  foreach(test_name domain_test domain_admission_test)
    target_link_libraries(${test_name} PRIVATE domain-admission-test-obj)
    target_link_options(${test_name} PRIVATE ${VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 30)
  endforeach()
  # 创建路径单独启用真实 fork/exec；避免现有 mock 业务测试运行 virt-install。
  add_library(domain-fork-test-obj OBJECT domain.cpp admission_test_support.cpp)
  target_include_directories(domain-fork-test-obj PRIVATE
    ${PROJECT_SOURCE_DIR}/src ${CMAKE_DEPS_INCLUDEDIR} ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/virtrust)
  target_link_libraries(domain-fork-test-obj PRIVATE virtrust-shared Deps::gtest Deps::secure_c)
  target_compile_definitions(domain-fork-test-obj PRIVATE VIRTRUST_REAL_FILE_LOCK_TEST VIRTRUST_API_FORK_TEST)
  add_virtrust_test_if(domain_fork_admission_test)
  target_link_libraries(domain_fork_admission_test PRIVATE domain-fork-test-obj)
  target_link_options(domain_fork_admission_test PRIVATE ${VIRTRUST_ADMISSION_TEST_WRAP_OPTIONS}
    "LINKER:--wrap=execv" "LINKER:--wrap=waitpid" "LINKER:--wrap=CreateVRoot")
  set_tests_properties(domain_fork_admission_test PROPERTIES TIMEOUT 15)
endif()

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/context.h ${CMAKE_CURRENT_LIST_DIR}/domain.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/virtrust/api/
  PERMISSIONS OWNER_READ)
