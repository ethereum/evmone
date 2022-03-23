// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/utils.h>
#include <cstddef>
#include <cstdint>
#include <string>

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

struct EOF1Header
{
    uint16_t code_size = 0;
    uint16_t data_size = 0;

    /// Returns offset of code section start.
    [[nodiscard]] EVMC_EXPORT size_t code_begin() const noexcept;
};

/// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
[[nodiscard]] EVMC_EXPORT bool is_eof_code(bytes_view code) noexcept;

/// Reads the section sizes assuming that code has valid format.
/// (must be true for all EOF contracts on-chain)
[[nodiscard]] EVMC_EXPORT EOF1Header read_valid_eof1_header(
    bytes_view::const_iterator code) noexcept;
}  // namespace evmone
