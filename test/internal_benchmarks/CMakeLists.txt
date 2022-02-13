# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(
    evmone-bench-internal
    find_jumpdest_bench.cpp
    instructions_bench.cpp
    memory_allocation.cpp
)
target_compile_options(
    evmone-bench-internal PRIVATE
    -fno-exceptions
    -falign-functions=32  # Default alignment (16) gives some boost to some ADD implementation.
)
target_link_libraries(evmone-bench-internal PRIVATE evmone benchmark::benchmark)
