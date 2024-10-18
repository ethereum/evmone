// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/bytes.hpp>
#include <vector>

namespace evmone::exp::jda
{
using evmc::bytes_view;

/// Bitset of valid jumpdest positions.
class JumpdestBitset : std::vector<bool>
{
public:
    using std::vector<bool>::operator[];

    JumpdestBitset(size_t size) : std::vector<bool>(size) {}

    bool check_jumpdest(size_t index) const noexcept { return index < size() && (*this)[index]; }
};

JumpdestBitset reference(bytes_view code);
JumpdestBitset speculate_push_data_size(bytes_view code);
}  // namespace evmone::exp::jda
