# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(evmone-statetestutils STATIC)
add_library(evmone::statetestutils ALIAS evmone-statetestutils)
target_compile_features(evmone-statetestutils PUBLIC cxx_std_20)
target_link_libraries(evmone-statetestutils PRIVATE evmone::state nlohmann_json::nlohmann_json)
target_include_directories(evmone-statetestutils PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-statetestutils PRIVATE
    statetest.hpp
    statetest_loader.cpp
    statetest_logs_hash.cpp
)

add_executable(evmone-statetest)
target_link_libraries(evmone-statetest PRIVATE evmone::statetestutils evmone GTest::gtest)
target_include_directories(evmone-statetest PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-statetest PRIVATE
    statetest.cpp
    statetest_runner.cpp
)
