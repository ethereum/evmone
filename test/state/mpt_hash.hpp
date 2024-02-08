// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "hash_utils.hpp"
#include <span>
#include <unordered_map>

namespace evmone::test
{
class TestState;
}

namespace evmone::state
{
/// Computes Merkle Patricia Trie root hash for the given collection of state accounts.
hash256 mpt_hash(const test::TestState& state);

/// Computes Merkle Patricia Trie root hash for the given list of structures.
template <typename T>
hash256 mpt_hash(std::span<const T> list);

/// A helper to automatically convert collections (e.g. vector, array) to span.
template <typename T>
inline hash256 mpt_hash(const T& list)
    requires std::is_convertible_v<T, std::span<const typename T::value_type>>
{
    return mpt_hash(std::span<const typename T::value_type>{list});
}

}  // namespace evmone::state
