// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

namespace evmone::crypto
{
bool modexp(evmc::bytes_view base, evmc::bytes_view exp, evmc::bytes_view mod, uint8_t* output);
}
