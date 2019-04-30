# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

include(GoogleTest)

set(evmone_private_include_dir ${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(benchmarks)
add_subdirectory(unittests)

gtest_add_tests(
    TARGET evmc-vmtester
    SOURCES ${PROJECT_SOURCE_DIR}/evmc/test/vmtester/tests.cpp
    EXTRA_ARGS $<TARGET_FILE:evmone>
    TEST_PREFIX ${PROJECT_NAME}/evmc-vmtester/)
