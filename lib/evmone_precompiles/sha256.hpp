// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The Silkworm & evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>

namespace evmone::crypto
{
void sha256(uint8_t hash[32], const uint8_t* input, size_t len, bool use_cpu_extensions);
}
