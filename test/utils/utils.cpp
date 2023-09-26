// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "utils.hpp"

namespace evmone::test
{

evmc_revision to_rev(std::string_view s)
{
    if (s == "Frontier")
        return EVMC_FRONTIER;
    if (s == "Homestead")
        return EVMC_HOMESTEAD;
    if (s == "EIP150")
        return EVMC_TANGERINE_WHISTLE;
    if (s == "EIP158")
        return EVMC_SPURIOUS_DRAGON;
    if (s == "Byzantium")
        return EVMC_BYZANTIUM;
    if (s == "Constantinople")
        return EVMC_CONSTANTINOPLE;
    if (s == "ConstantinopleFix")
        return EVMC_PETERSBURG;
    if (s == "Istanbul")
        return EVMC_ISTANBUL;
    if (s == "Berlin")
        return EVMC_BERLIN;
    if (s == "London" || s == "ArrowGlacier")
        return EVMC_LONDON;
    if (s == "Merge")
        return EVMC_PARIS;
    if (s == "Merge+3855")  // PUSH0
        return EVMC_SHANGHAI;
    if (s == "Shanghai")
        return EVMC_SHANGHAI;
    if (s == "Cancun")
        return EVMC_CANCUN;
    if (s == "Prague")
        return EVMC_PRAGUE;
    throw std::invalid_argument{"unknown revision: " + std::string{s}};
}

}  // namespace evmone::test
