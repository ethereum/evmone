// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "hash_utils.hpp"

std::ostream& operator<<(std::ostream& out, const evmone::address& a)
{
    return out << "0x" << hex(a);
}

std::ostream& operator<<(std::ostream& out, const evmone::bytes32& b)
{
    return out << "0x" << hex(b);
}
