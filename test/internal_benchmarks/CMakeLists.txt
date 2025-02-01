# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(
    evmone-bench-internal
    eof_validation_bench.cpp
    evmmax_bench.cpp
    find_jumpdest_bench.cpp
    memory_allocation.cpp
)

target_link_libraries(evmone-bench-internal PRIVATE evmone evmone::evmmax evmone::testutils benchmark::benchmark)
target_include_directories(evmone-bench-internal PRIVATE ${evmone_private_include_dir})
