# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

find_package(intx CONFIG REQUIRED)

add_library(testutils STATIC
    bytecode.hpp
    utils.cpp
    utils.hpp
)

target_link_libraries(testutils PRIVATE evmc::evmc_cpp)
target_include_directories(testutils PUBLIC ${PROJECT_SOURCE_DIR} ${evmone_private_include_dir})
