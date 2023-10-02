# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone_precompiles STATIC)
add_library(evmone::precompiles ALIAS evmone_precompiles)
target_link_libraries(evmone_precompiles PUBLIC evmc::evmc_cpp PRIVATE evmone::evmmax)
target_sources(
    evmone_precompiles PRIVATE
    ecc.hpp
    secp256k1.cpp
    secp256k1.hpp
)
