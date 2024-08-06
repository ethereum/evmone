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
    VERSION 0.11.0
    URL https://github.com/chfast/intx/archive/v0.11.0.tar.gz
    SHA1 025fe6e95e7066b49e6bb3deff597a24442312ff
)
