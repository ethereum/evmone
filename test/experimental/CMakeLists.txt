# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-experimental STATIC)
add_library(evmone::experimental ALIAS evmone-experimental)

target_sources(evmone-experimental PRIVATE dummy.cpp opcode_manip.hpp)
target_include_directories(evmone-experimental PUBLIC ${PROJECT_SOURCE_DIR})
