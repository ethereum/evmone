# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state STATIC)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state PRIVATE evmc::evmc_cpp ethash::keccak)
target_sources(
    evmone-state PRIVATE
    hash_utils.hpp
    mpt.hpp
    mpt.cpp
    rlp.hpp
)
