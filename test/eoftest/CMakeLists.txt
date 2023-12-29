# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(evmone-eoftest)
target_link_libraries(evmone-eoftest PRIVATE evmone evmone::testutils nlohmann_json::nlohmann_json GTest::gtest)
target_include_directories(evmone-eoftest PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-eoftest PRIVATE
    eoftest.cpp
    eoftest_runner.cpp
)
