// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include "../../../silkpre/lib/silkpre/precompile.h"
#include <intx/intx.hpp>
#include <cassert>
#include <limits>

extern "C" {

// Declare functions from Rust precompiles.

SilkpreResult ecadd_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ecpairing_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ripemd160_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
}

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

PrecompiledCost sha256_cost(const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {60 + 12 * ((static_cast<int64_t>(input_size) + 31) / 32), 32};
}

PrecompiledCost identity_cost(const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {15 + 3 * ((static_cast<int64_t>(input_size) + 31) / 32), input_size};
}

PrecompiledCost ecadd_cost(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 150 : 500, 64};
}

PrecompiledCost ecmul_cost(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 6'000 : 40'000, 64};
}

PrecompiledCost ecpairing_cost(const uint8_t*, size_t input_size, evmc_revision rev) noexcept
{
    const auto k = input_size / 192;
    return {static_cast<int64_t>(rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000),
        32};
}

PrecompiledCost blake2bf_cost(const uint8_t* input, size_t input_size, evmc_revision) noexcept
{
    if (input_size < 4)
        return {std::numeric_limits<int64_t>::max(), 0};
    return {intx::be::unsafe::load<uint32_t>(input), 64};
}

intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept
{
    const intx::uint256 x_squared{x * x};
    if (x <= 64)
    {
        return x_squared;
    }
    else if (x <= 1024)
    {
        return (x_squared >> 2) + 96 * x - 3072;
    }
    else
    {
        return (x_squared >> 4) + 480 * x - 199680;
    }
}

intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept
{
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

PrecompiledCost internal_expmod_gas(const uint8_t* ptr, size_t len, evmc_revision rev) noexcept
{
    const int64_t min_gas{rev < EVMC_BERLIN ? 0 : 200};

    std::basic_string<uint8_t> input(ptr, len);
    if (input.size() < 3 * 32)
        input.resize(3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0)
    {
        return {min_gas, 0};
    }

    if (intx::count_significant_words(base_len256) > 1 ||
        intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1)
    {
        return {std::numeric_limits<int64_t>::max(), 0};
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64)
    {
        input.erase(0, base_len64);
        if (input.size() < 3 * 32)
            input.resize(3 * 32);
        if (exp_len64 < 32)
        {
            input.erase(exp_len64);
            input.insert(0, 32 - exp_len64, '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32)
    {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1)
    {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1)
    {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN)
    {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    }
    else
    {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (gas > std::numeric_limits<int64_t>::max())
    {
        return {std::numeric_limits<int64_t>::max(), 0};
    }
    else
    {
        return {std::max(min_gas, static_cast<int64_t>(gas)), static_cast<size_t>(mod_len256)};
    }
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
        [](const uint8_t*, size_t, evmc_revision) noexcept {
            return PrecompiledCost{3000, 32};
        },
        ethprecompiled_ecrecover};
    tbl[2] = {"sha256", sha256_cost, ethprecompiled_sha256};
    tbl[3] = {"ripemd160",
        [](const uint8_t*, size_t input_size, evmc_revision) noexcept {
            return PrecompiledCost{cost_per_input_word(600, 120, input_size), 32};
        },
        ripemd160_execute};
    tbl[4] = {"identity", identity_cost, identity_exec};
    tbl[5] = {"expmod", internal_expmod_gas, ethprecompiled_expmod};
    tbl[6] = {"ecadd", ecadd_cost, ecadd_execute};
    tbl[7] = {"ecmul", ecmul_cost, ethprecompiled_ecmul};
    tbl[8] = {"ecpairing", ecpairing_cost, ecpairing_execute};
    tbl[9] = {"blake2bf", blake2bf_cost, ethprecompiled_blake2bf};
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

    uint8_t output_buf[256];  // Big enough to handle all "expmod" tests.

    const auto t = traits[id];
    const auto [gas_cost, max_output_size] = t.cost(msg.input_data, msg.input_size, rev);
    const auto gas_left = msg.gas - gas_cost;
    if (gas_left < 0)
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    assert(std::size(output_buf) >= max_output_size);
    const auto [status_code, output_size] =
        t.exec(msg.input_data, msg.input_size, output_buf, max_output_size);
    if (status_code != EVMC_SUCCESS)
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    return evmc::result{EVMC_SUCCESS, gas_left, output_buf, output_size};
}
}  // namespace evmone::state
