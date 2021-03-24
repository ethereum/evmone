# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

find_package(intx CONFIG REQUIRED)

add_library(testutils STATIC
    bytecode.hpp
    utils.cpp
    utils.hpp
)

target_link_libraries(testutils PRIVATE evmc::instructions evmc::hex)
target_include_directories(testutils PUBLIC ${PROJECT_SOURCE_DIR})

add_library(testutils-dump STATIC dump.cpp dump.hpp)
target_link_libraries(testutils-dump PRIVATE testutils evmone intx::intx)
target_include_directories(testutils-dump PRIVATE ${evmone_private_include_dir})
