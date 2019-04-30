# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(benchmark)
find_package(benchmark CONFIG REQUIRED)

add_executable(evmone-bench benchmarks.cpp)

target_link_libraries(evmone-bench PRIVATE evmone benchmark::benchmark)
set_target_properties(evmone-bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY ..)
