// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stddef.h>
#include <cstdint>

namespace evmone
{
struct EOF1Header
{
    size_t code_size = 0;
    size_t data_size = 0;
};

// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
bool is_eof_code(const uint8_t* code, size_t code_size) noexcept;

// Reads the section sizes assuming that code has valid format.
// (must be true for all EOF contracts on-chain)
EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept;
}  // namespace evmone
