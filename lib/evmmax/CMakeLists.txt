# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmmax STATIC)
add_library(evmone::evmmax ALIAS evmmax)
target_compile_features(evmmax PUBLIC cxx_std_20)
target_link_libraries(evmmax PRIVATE intx::intx)
target_sources(
    evmmax PRIVATE
    evmmax.hpp
    evmmax.cpp
    bn254.hpp
    bn254.cpp
)
