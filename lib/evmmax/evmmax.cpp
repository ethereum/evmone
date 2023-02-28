// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evmmax.hpp"

namespace evmmax
{
std::unique_ptr<ModState> setup(bytes_view modulus, size_t vals_used)
{
    (void)modulus;
    (void)vals_used;
    return nullptr;
}
}  // namespace evmmax
