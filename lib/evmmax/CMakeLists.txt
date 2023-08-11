# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmmax STATIC)
add_library(evmone::evmmax ALIAS evmmax)
target_compile_features(evmmax PUBLIC cxx_std_20)
target_include_directories(evmmax PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(evmmax PRIVATE intx::intx evmc::evmc_cpp)
target_sources(
    evmmax PRIVATE
    ${PROJECT_SOURCE_DIR}/include/evmmax/evmmax.hpp
    ecc.hpp
    evmmax.cpp
    bn254.hpp
    bn254.cpp
    poly_extension_field.hpp
    secp256k1.hpp
    secp256k1.cpp
)
