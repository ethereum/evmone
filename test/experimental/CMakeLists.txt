# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-experimental STATIC)
add_library(evmone::experimental ALIAS evmone-experimental)

target_include_directories(evmone-experimental PUBLIC ${PROJECT_SOURCE_DIR})
target_link_libraries(evmone-experimental PRIVATE evmc::instructions)
target_sources(
    evmone-experimental PRIVATE
    jumpdest_analysis.cpp
    opcode_manip.hpp
)
