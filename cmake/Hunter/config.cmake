# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_config(
    intx
    VERSION 0.6.0
    URL https://github.com/chfast/intx/archive/v0.6.0.tar.gz
    SHA1 507827495de07412863349bc8c2a8704c7b0e5d4
)

hunter_config(
    ethash
    VERSION 0.7.0
    URL https://github.com/chfast/ethash/archive/refs/tags/v0.7.0.tar.gz
    SHA1 83768c203c98dff1829f038fde98a7226e1edd98
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF -DETHASH_BUILD_TESTS=OFF
)

hunter_config(
    benchmark
    VERSION 1.5.5
    URL https://github.com/google/benchmark/archive/refs/tags/v1.5.5.tar.gz
    SHA1 5d9957a347f9abd3a491596cb5e40078cee0ec01
    CMAKE_ARGS -DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_ENABLE_LIBPFM=ON
)

