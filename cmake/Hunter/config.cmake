# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(hunter_cmake_args)

hunter_config(
    ethash
    VERSION 1.0.1
    URL https://github.com/chfast/ethash/archive/v1.0.0.tar.gz
    SHA1 75e64b885be0ad90f0fad8e8e718f02d4b0edac8
)

hunter_cmake_args(
    ethash
    CMAKE_ARGS ETHASH_BUILD_ETHASH=OFF ETHASH_BUILD_TESTS=OFF
)

hunter_config(
    intx
    VERSION 0.9.1
    URL https://github.com/chfast/intx/archive/v0.9.1.tar.gz
    SHA1 d9907860327b52ca5cba4048d1a0e8274c883584
)
