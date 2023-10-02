# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(evmone-blockchaintest)
target_link_libraries(evmone-blockchaintest PRIVATE evmone evmone::statetestutils GTest::gtest)
target_include_directories(evmone-blockchaintest PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-blockchaintest PRIVATE
    blockchaintest.hpp
    blockchaintest.cpp
    blockchaintest_runner.cpp
)
