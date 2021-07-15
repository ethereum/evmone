// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <stddef.h>
#include <cstdint>
#include <utility>

namespace evmone
{
struct EOF1Header
{
    int code_size = 0;
    int data_size = 0;

    EVMC_EXPORT size_t code_begin() const noexcept;
    EVMC_EXPORT size_t code_end() const noexcept;
};

// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
bool is_eof_code(const uint8_t* code, size_t code_size) noexcept;

// Reads the section sizes assuming that code has valid format.
// (must be true for all EOF contracts on-chain)
EVMC_EXPORT EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept;

enum class EOFValidationErrror
{
    success,
    starts_with_format,
    invalid_prefix,
    eof_version_mismatch,
    eof_version_unknown,

    incomplete_section_size,
    code_section_missing,
    multiple_code_sections,
    multiple_data_sections,
    unknown_section_id,
    zero_section_size,
    section_headers_not_terminated,
    invalid_section_bodies_size,

    initcode_failure,
    impossible,
};

/// Determine the EOF version of the code by inspecting code's EOF prefix.
/// If the prefix is missing or invalid, the 0 is returned meaning legacy code.
uint8_t get_eof_version(const uint8_t* code, size_t code_size) noexcept;

std::pair<EOF1Header, EOFValidationErrror> validate_eof1(
    const uint8_t* code, size_t code_size) noexcept;

EVMC_EXPORT EOFValidationErrror validate_eof(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone
