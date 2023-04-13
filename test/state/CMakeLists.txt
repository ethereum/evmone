# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state STATIC)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state PUBLIC evmc::evmc_cpp PRIVATE evmone ethash::keccak)
target_include_directories(evmone-state PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-state PRIVATE
    account.hpp
    bloom_filter.hpp
    bloom_filter.cpp
    errors.hpp
    hash_utils.hpp
    hash_utils.cpp
    host.hpp
    host.cpp
    mpt.hpp
    mpt.cpp
    mpt_hash.hpp
    mpt_hash.cpp
    precompiles.hpp
    precompiles.cpp
    precompiles_cache.hpp
    precompiles_cache.cpp
    rlp.hpp
    state.hpp
    state.cpp
)
