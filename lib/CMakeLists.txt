# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_subdirectory(evmone_precompiles)
add_subdirectory(evmmax)
add_subdirectory(evmone)
