// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/instructions.h>
#include <cstdint>
#include <stdexcept>
#include <string>

using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;

/// Encode a byte to a hex string.
inline std::string hex(uint8_t b) noexcept
{
    static constexpr auto hex_chars = "0123456789abcdef";
    return {hex_chars[b >> 4], hex_chars[b & 0xf]};
}

inline std::string hex(evmc_opcode opcode) noexcept
{
    return hex(static_cast<uint8_t>(opcode));
}

bytes from_hex(std::string_view hex);
std::string to_hex(bytes_view bytes);
