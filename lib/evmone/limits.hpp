// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

/// The maximum EVM bytecode size allowed by the Ethereum spec.
constexpr auto max_code_size = 0x6000;

/// The maximum base cost of any EVM instruction.
/// The value comes from the cost of the SSTORE instruction.
constexpr auto max_instruction_base_cost = 20000;
