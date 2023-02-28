# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmmax STATIC)
add_library(evmone::evmmax ALIAS evmmax)
target_link_libraries(evmmax PRIVATE intx::intx)
target_sources(
    evmmax PRIVATE
    evmmax.hpp
    evmmax.cpp
)
