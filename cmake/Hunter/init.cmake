# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

set(HUNTER_CONFIGURATION_TYPES Release CACHE STRING "Build type of Hunter packages")

include(HunterGate)

HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.11.tar.gz"
    SHA1 "e49fb20a135675e406e95fbe9a591a630ccbbeaf"
    LOCAL
)
