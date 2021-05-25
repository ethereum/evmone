# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_config(
    intx
    VERSION 0.5.1
    URL https://github.com/chfast/intx/archive/v0.5.1.tar.gz
    SHA1 743c46a82750143bd302a4394b7008a2112fc97b
)

hunter_config(
    ethash
    VERSION 425f9cbb
    URL https://github.com/chfast/ethash/archive/425f9cbb7a0a14719a94d6079b06dc1c16500061.tar.gz
    SHA1 5c59a63d5af833a44dc5a5f5496087b35c423f8f
    CMAKE_ARGS -DETHASH_BUILD_ETHASH=OFF -DETHASH_BUILD_TESTS=OFF
)
