# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2024 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(crypto STATIC)
add_library(evmone::crypto ALIAS crypto)
target_compile_features(crypto PRIVATE cxx_std_20)
target_link_libraries(crypto PUBLIC evmc::evmc_cpp)
target_sources(
    crypto PRIVATE
    sha256.hpp
    sha256.cpp
)
