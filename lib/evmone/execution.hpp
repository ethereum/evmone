// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>

namespace evmone
{
evmc_result execute(int64_t gas, const uint8_t* code, size_t code_size) noexcept;
}  // namespace evmone
