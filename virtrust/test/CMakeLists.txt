# Copyright (c)

# 服务管理脚本使用 Bash；缺少解释器时明确失败，避免漏跑回归测试。
find_program(VIRTRUST_TEST_BASH_EXECUTABLE NAMES bash REQUIRED)
foreach(service_test IN ITEMS install install_atomic uninstall status reload logs unit_update ownership effective_unit)
  set(service_test_name "virtrustd_service_${service_test}_test")
  add_test(
    NAME ${service_test_name}
    COMMAND "${VIRTRUST_TEST_BASH_EXECUTABLE}"
            "${CMAKE_CURRENT_LIST_DIR}/${service_test_name}.sh")
  # 测试仅使用临时文件和替代命令；超时用于防止测试进程意外挂起。
  set_tests_properties(${service_test_name} PROPERTIES TIMEOUT 15)
endforeach()

find_program(OPENSSL_EXECUTABLE NAMES openssl REQUIRED)

# 逐步检查生成结果；前序失败立即结束配置，避免使用不完整或旧的测试凭据。
function(virtrust_generate_test_certificate stage working_directory)
  execute_process(
    COMMAND "${OPENSSL_EXECUTABLE}" ${ARGN}
    WORKING_DIRECTORY "${working_directory}"
    RESULT_VARIABLE certificate_result
    ERROR_VARIABLE certificate_error
    OUTPUT_QUIET)
  if(NOT "${certificate_result}" STREQUAL "0")
    message(FATAL_ERROR
      "Test certificate generation failed: stage=${stage}; directory=${working_directory}; result=${certificate_result}\n${certificate_error}")
  endif()
endfunction()

file(MAKE_DIRECTORY "${VIRTRUST_TEST_CERT_DIR}/ca"
                    "${VIRTRUST_TEST_CERT_DIR}/server"
                    "${VIRTRUST_TEST_CERT_DIR}/client")
message(STATUS "Generating test certificates at: ${VIRTRUST_TEST_CERT_DIR}")

# 仅生成测试用 CA 和无口令私钥，生产证书仍由部署者提供。
virtrust_generate_test_certificate("CA certificate" "${VIRTRUST_TEST_CERT_DIR}/ca"
  req -x509 -newkey rsa:2048 -nodes -keyout sk.pem -out cert.pem -days 365
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com")

# 服务端和客户端分别生成密钥、签名请求，再由上述测试 CA 签发。
foreach(certificate_role IN ITEMS server client)
  set(certificate_directory "${VIRTRUST_TEST_CERT_DIR}/${certificate_role}")
  virtrust_generate_test_certificate("${certificate_role} private key" "${certificate_directory}"
    genrsa -out sk.pem 2048)
  virtrust_generate_test_certificate("${certificate_role} signing request" "${certificate_directory}"
    req -new -key sk.pem -out "${certificate_role}.csr"
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com")
  virtrust_generate_test_certificate("${certificate_role} certificate" "${certificate_directory}"
    x509 -req -in "${certificate_role}.csr" -CA ../ca/cert.pem
    -CAkey ../ca/sk.pem -CAcreateserial -out cert.pem -days 365 -sha256)
endforeach()

message(STATUS "Generated test certificates at: ${VIRTRUST_TEST_CERT_DIR}")
