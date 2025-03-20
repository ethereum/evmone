# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-evmmax-precompiles STATIC)
add_library(evmone::evmone-evmmax-precompiles ALIAS evmone-evmmax-precompiles)
target_link_libraries(evmone-evmmax-precompiles PRIVATE evmone testutils)
target_include_directories(evmone-evmmax-precompiles PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-evmmax-precompiles PRIVATE
    ntt.hpp
    ntt.cpp
    poseidon.hpp
    poseidon.cpp
)
