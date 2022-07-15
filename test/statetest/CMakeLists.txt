# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(evmone-statetest)
target_link_libraries(evmone-statetest PRIVATE evmone evmone::state nlohmann_json::nlohmann_json GTest::gtest)
target_sources(
    evmone-statetest PRIVATE
    statetest.hpp
    statetest.cpp
    statetest_loader.cpp
)
