// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_utils.hpp"
#include <evmc/evmc.hpp>
#include <span>
#include <vector>

namespace evmone::state
{
/// `requests` object.
struct Requests
{
    /// Request type.
    uint8_t type = 0;
    /// Request data - an opaque byte array, contains zero or more encoded request objects.
    evmc::bytes data;
};

/// Block requests list - container of `requests` objects, ordered by request type.
using RequestsList = std::vector<Requests>;

/// Calculate commitment value of block requests list
hash256 calculate_requests_hash(std::span<const Requests> block_requests_list);

}  // namespace evmone::state
