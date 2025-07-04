// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>
#include <span>

namespace evmone::crypto
{
/// Performs modular exponentiation (modexp) operation, which computes
/// (base^exp) % mod. Handles various sizes of inputs dynamically.
///
/// @param base The base in the modular exponentiation operation, represented
///             as a span of bytes in big-endian format. The maximum supported
///             input size is 1024 bytes.
/// @param exp  The exponent in the modular exponentiation operation,
///             represented as a span of bytes in big-endian format. Leading
///             zero bytes in the exponent are ignored.
/// @param mod  The modulus in the modular exponentiation operation, represented
///             as a span of bytes in big-endian format. The maximum supported
///             input size is 1024 bytes. The modulus must not be zero.
/// @param output Pointer to an output buffer where the result of the computation
///               is stored. The output size matches the size of the modulus to
///               ensure consistent representation in big-endian format.
void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept;
}  // namespace evmone::crypto
