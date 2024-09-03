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
    VERSION 0.12.0
    URL https://github.com/chfast/intx/archive/v0.12.0.tar.gz
    SHA1 18a64e8e88c50d53325d906c9211daef905b97f4
)
