// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "hash_utils.hpp"
#include <unordered_map>

namespace evmone::state
{
struct Account;

/// Computes Merkle Patricia Trie root hash for the given collection of state accounts.
hash256 mpt_hash(const std::unordered_map<address, Account>& accounts);
}  // namespace evmone::state
