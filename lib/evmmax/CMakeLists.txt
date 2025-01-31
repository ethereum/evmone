# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmmax STATIC)
add_library(evmone::evmmax ALIAS evmmax)
target_compile_features(evmmax PUBLIC cxx_std_20)
target_include_directories(evmmax PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(evmmax PUBLIC intx::intx PRIVATE evmc::evmc_cpp)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.19)
    # We want to add the header file to the library for IDEs.
    # However, cmake 3.18 does not support PRIVATE scope for INTERFACE libraries.
    target_sources(
        evmmax PRIVATE
        ${PROJECT_SOURCE_DIR}/include/evmmax/evmmax.hpp
        evmmax.cpp
    )
endif()
