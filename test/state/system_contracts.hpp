// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>

namespace evmone::state
{
class BlockInfo;
class State;

/// Performs the system call: invokes system contracts.
///
/// Executes code of pre-defined accounts via pseudo-transaction from the system sender (0xff...fe).
/// The sender's nonce is not increased.
void system_call(State& state, const BlockInfo& block, evmc_revision rev, evmc::VM& vm);
}  // namespace evmone::state
