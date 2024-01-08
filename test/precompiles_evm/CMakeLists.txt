# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2024 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

find_package(intx CONFIG REQUIRED)

add_library(evmone-precompiles-evm STATIC)
add_library(evmone::evmone-precompiles-evm ALIAS evmone-precompiles-evm)
target_link_libraries(evmone-precompiles-evm PRIVATE evmone testutils intx::intx)
target_include_directories(evmone-precompiles-evm INTERFACE ${PROJECT_SOURCE_DIR} ${evmone_private_include_dir})

target_sources(
    evmone-precompiles-evm PRIVATE
    bn254_evm.hpp
    bn254_evm.cpp
    ecc_evm.hpp
    ecc_evm.cpp
    precompiles_evm.hpp
    precompiles_evm.cpp
    utils.hpp
)
