# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

add_executable(
    evmone-bench-internal
    find_jumpdest_bench.cpp
    memory_allocation.cpp
)

target_link_libraries(evmone-bench-internal PRIVATE benchmark::benchmark)
