// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <cstring>

namespace evmone
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using evmc::bytes_view;
using namespace evmc::literals;

/// Default type for 256-bit hash.
///
/// Better than ethash::hash256 because has some additional handy constructors.
using hash256 = bytes32;

/// Computes Keccak hash out of input bytes (wrapper of ethash::keccak256).
inline hash256 keccak256(bytes_view data) noexcept
{
    const auto eh = ethash::keccak256(data.data(), data.size());
    hash256 h;
    std::memcpy(h.bytes, eh.bytes, sizeof(h));  // TODO: Use std::bit_cast.
    return h;
}
}  // namespace evmone

std::ostream& operator<<(std::ostream& out, const evmone::address& a);
std::ostream& operator<<(std::ostream& out, const evmone::bytes32& b);
