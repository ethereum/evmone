# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(hunter_cmake_args)

hunter_config(
    intx
    VERSION LS
    URL https://github.com/chfast/intx/archive/load_store.tar.gz
    SHA1 ca6e35bfcdf0d3273c61dff0983e32a74d2887ce
)


hunter_cmake_args(
    ethash
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF
)
