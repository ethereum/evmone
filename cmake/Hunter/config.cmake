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
    VERSION 0.10.0
    URL https://github.com/chfast/intx/archive/v0.10.0.tar.gz
    SHA1 3a6ebe0b1a36527b6ef291ee93a8e508371e5b77
)
