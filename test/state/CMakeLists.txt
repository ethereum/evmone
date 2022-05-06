# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state INTERFACE)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state INTERFACE ethash::keccak)
target_sources(
    evmone-state INTERFACE
    hash_utils.hpp
)
