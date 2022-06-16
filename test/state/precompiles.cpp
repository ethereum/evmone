// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include "../../../silkpre/lib/silkpre/precompile.h"
#include <cassert>

namespace evmone::state
{
using namespace evmc::literals;

namespace
{
struct PrecompiledCost
{
    int64_t gas_cost;
    size_t output_size;
};

int64_t cost_per_input_word(int64_t base_cost, int64_t word_cost, size_t input_size) noexcept
{
    return base_cost + word_cost * ((static_cast<int64_t>(input_size) + 31) / 32);
}

PrecompiledCost sha256_cost(size_t input_size) noexcept
{
    return {60 + 12 * ((static_cast<int64_t>(input_size) + 31) / 32), 32};
}

PrecompiledCost identity_cost(size_t input_size) noexcept
{
    return {15 + 3 * ((static_cast<int64_t>(input_size) + 31) / 32), input_size};
}

SilkpreResult identity_exec(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size == input_size);
    std::copy_n(input, input_size, output);
    return {0, input_size};
}

struct PrecompiledTraits
{
    const char* name;
    decltype(sha256_cost)* cost;
    decltype(ethprecompiled_ecrecover)* exec;
};

constexpr auto traits = [] {
    std::array<PrecompiledTraits, 10> tbl{};
    tbl[1] = {"ecrecover",
        [](size_t) noexcept {
            return PrecompiledCost{3000, 32};
        },
        ethprecompiled_ecrecover};
    tbl[2] = {"sha256", sha256_cost, ethprecompiled_sha256};
    tbl[3] = {"ripemd160",
        [](size_t input_size) noexcept {
            return PrecompiledCost{cost_per_input_word(600, 120, input_size), 32};
        },
        ethprecompiled_ripemd160};
    tbl[4] = {"identity", identity_cost, identity_exec};
    return tbl;
}();
}  // namespace

std::optional<evmc::result> call_precompiled(evmc_revision rev, const evmc_message& msg) noexcept
{
    if (evmc::is_zero(msg.code_address) || msg.code_address > 0x09_address)
        return {};

    const auto id = msg.code_address.bytes[19];
    assert(id > 0);
    assert(msg.gas >= 0);

    uint8_t output_buf[128];  // Big enough to handle all "identity" tests.

    switch (id)
    {
    case 1:
    case 2:
    case 3:
    case 4:
    {
        const auto t = traits[id];
        const auto cost = t.cost(msg.input_size);
        const auto gas_left = msg.gas - cost.gas_cost;
        if (gas_left < 0)
            return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        assert(std::size(output_buf) >= cost.output_size);
        const auto r = t.exec(
            msg.input_data, static_cast<uint32_t>(msg.input_size), output_buf, cost.output_size);
        assert(r.status_code == 0);
        return evmc::result{EVMC_SUCCESS, gas_left, output_buf, r.output_size};
    }
    default:
    {
        const auto index = id - 1;
        assert(index < SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS);

        const auto contract = kSilkpreContracts[index];
        const uint64_t cost = contract.gas(msg.input_data, msg.input_size, rev);

        if (static_cast<uint64_t>(msg.gas) < cost)
            return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        const auto gas_left = msg.gas - static_cast<int64_t>(cost);

        const auto out = contract.run(msg.input_data, msg.input_size);
        if (out.data == nullptr)  // Null output also means failure.
            return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        evmc::result result{EVMC_SUCCESS, gas_left, out.data, out.size};
        std::free(out.data);
        return result;
    }
    }
}
}  // namespace evmone::state
