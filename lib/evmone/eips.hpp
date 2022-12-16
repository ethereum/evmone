// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>

namespace evmone
{

/// The list Ethereum EIPs being implemented in evmone.
///
/// This is not enum class because we want implicit conversion to integers,
/// e.g. for usage as an array index.
enum Eip : int
{
    EIP3540 = (1 << 8),
    EIP3670 = (1 << 9),
    EIP3855 = (1 << 10),
    EIP3860 = (1 << 11)
};

inline constexpr evmc_revision add_eip(evmc_revision rev, Eip eip)
{
    return static_cast<evmc_revision>(rev | static_cast<int>(eip));
}

inline constexpr bool has_eip(evmc_revision rev, Eip eip)
{
    return (rev & static_cast<int>(eip)) > 0;
}

inline constexpr evmc_revision clear_eips(evmc_revision rev)
{
    return static_cast<evmc_revision>(rev & 0xff);
}

}  // namespace evmone
