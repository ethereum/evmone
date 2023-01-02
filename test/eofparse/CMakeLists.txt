# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2023 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(evmone-eofparse eofparse.cpp)
target_link_libraries(evmone-eofparse PRIVATE evmone)
target_include_directories(evmone-eofparse PRIVATE ${evmone_private_include_dir})
