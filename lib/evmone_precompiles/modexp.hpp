// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

namespace evmone::crypto
{
bool modexp(uint8_t* output, size_t output_size, const evmc::bytes_view& base,
    const evmc::bytes_view& exp, const evmc::bytes_view& mod);
}
