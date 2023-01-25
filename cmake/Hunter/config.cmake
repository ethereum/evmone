# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(hunter_cmake_args)

hunter_cmake_args(
    ethash
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF
)

hunter_config(
    intx
    VERSION 0.9.1
    URL https://github.com/chfast/intx/archive/v0.9.1.tar.gz
    SHA1 d9907860327b52ca5cba4048d1a0e8274c883584
)
