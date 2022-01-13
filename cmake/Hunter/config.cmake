# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_config(
    intx
    VERSION 0.7.0
    URL https://github.com/chfast/intx/archive/v0.7.0.tar.gz
    SHA1 d5bacebd6b66f7f3b22c2f7db43696f98951e8c3
)

hunter_config(
    ethash
    VERSION 0.8.0
    URL https://github.com/chfast/ethash/archive/v0.8.0.tar.gz
    SHA1 41fd440f70b6a8dfc3fd29b20f471dcbd1345ad0
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF -DETHASH_BUILD_TESTS=OFF
)

hunter_config(
    GTest
    VERSION 1.11.0
    URL https://github.com/google/googletest/archive/release-1.11.0.tar.gz
    SHA1 7b100bb68db8df1060e178c495f3cbe941c9b058
    CMAKE_ARGS
    HUNTER_INSTALL_LICENSE_FILES=LICENSE
    gtest_force_shared_crt=TRUE
)

hunter_config(
    benchmark
    VERSION 1.6.1
    URL https://github.com/google/benchmark/archive/v1.6.1.tar.gz
    SHA1 1faaa54195824bbe151c1ebee31623232477d075
)
