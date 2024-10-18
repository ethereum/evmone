# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-experimental STATIC)
add_library(evmone::experimental ALIAS evmone-experimental)
target_link_libraries(evmone-experimental PRIVATE evmone)
target_include_directories(evmone-experimental PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-experimental PRIVATE
    jumpdest_analysis.hpp
    jumpdest_analysis.cpp
)
