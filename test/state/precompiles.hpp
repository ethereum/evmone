// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../utils/stdx/utility.hpp"
#include <evmc/evmc.hpp>
#include <optional>

namespace evmone::state
{
/// The precompile identifiers and their corresponding addresses.
enum class PrecompileId : uint8_t
{
    ecrecover = 0x01,
    sha256 = 0x02,
    ripemd160 = 0x03,
    identity = 0x04,
    expmod = 0x05,
    ecadd = 0x06,
    ecmul = 0x07,
    ecpairing = 0x08,
    blake2bf = 0x09,

    since_byzantium = expmod,   ///< The first precompile introduced in Byzantium.
    since_istanbul = blake2bf,  ///< The first precompile introduced in Istanbul.
    latest = blake2bf           ///< The latest introduced precompile (highest address).
};

/// The total number of known precompiles ids, including 0.
inline constexpr std::size_t NumPrecompiles = stdx::to_underlying(PrecompileId::latest) + 1;

struct ExecutionResult
{
    evmc_status_code status_code;
    size_t output_size;
};

/// Checks if the address @p addr is considered a precompiled contract in the revision @p rev.
bool is_precompile(evmc_revision rev, const evmc::address& addr) noexcept;

/// Executes the message to a precompiled contract (msg.code_address must be a precompile).
evmc::Result call_precompile(evmc_revision rev, const evmc_message& msg) noexcept;
}  // namespace evmone::state
