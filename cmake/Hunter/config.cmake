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
    URL https://github.com/chfast/intx/archive/v0.10.1.tar.gz
    SHA1 168e0c2ff6760bd6467e25523cc0e68447358018
)
