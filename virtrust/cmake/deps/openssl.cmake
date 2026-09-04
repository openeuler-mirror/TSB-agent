# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# openssl is dlopen'ed at runtime (see src/virtrust/dllib/openssl.h) and is
# provided by the system package (yum: openssl-devel)
find_package(OpenSSL REQUIRED)

add_library(libcrypto INTERFACE)
target_link_libraries(libcrypto INTERFACE OpenSSL::Crypto)

add_library(libssl INTERFACE)
target_link_libraries(libssl INTERFACE OpenSSL::SSL)

target_link_libraries(libssl INTERFACE libcrypto)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::openssl ALIAS libssl)
