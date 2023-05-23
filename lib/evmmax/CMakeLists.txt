# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

enable_language(ASM)

add_library(evmmax STATIC)
add_library(evmone::evmmax ALIAS evmmax)
target_compile_features(evmmax PUBLIC cxx_std_20)
target_compile_options(evmmax PRIVATE -Wno-unused-command-line-argument)
target_link_libraries(evmmax PRIVATE intx::intx)
target_sources(
    evmmax PRIVATE
    evmmax.hpp
    evmmax.cpp
        mulx_mont_256-x86_64.s
        mulMont256_spare_bits_asm_adx.S
    bn254.hpp
    bn254.cpp
)
