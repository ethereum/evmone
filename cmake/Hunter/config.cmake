# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(hunter_cmake_args)

hunter_cmake_args(
    ethash
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF
)

hunter_config(
    ethash
    VERSION 1.1.0
    URL https://github.com/chfast/ethash/archive/v1.1.0.tar.gz
    SHA1 b5625c876d7de3997800a9d7546f0657a7fdb3af
)

hunter_config(
    intx
    VERSION 0.12.1
    URL https://github.com/chfast/intx/archive/v0.12.1.tar.gz
    SHA1 b2465f217b0289c36579668537df4ce2f84547f0
)
