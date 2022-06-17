// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include <intx/intx.hpp>
#include <cassert>
#include <iostream>
#include <limits>
#include <unordered_map>

namespace evmone::state
{
using evmc::bytes;
using evmc::bytes_view;
using namespace evmc::literals;

namespace
{
constexpr auto GasCostMax = std::numeric_limits<int64_t>::max();

struct PrecompileAnalysis
{
    int64_t gas_cost;
    size_t max_output_size;
};

inline constexpr int64_t num_words(size_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + 31) / 32);
}

template <int BaseCost, int WordCost>
inline constexpr int64_t cost_per_input_word(size_t input_size) noexcept
{
    return BaseCost + WordCost * num_words(input_size);
}

inline constexpr PrecompileAnalysis ecrecover_analyze(
    const uint8_t* /*input*/, size_t /*input_size*/, evmc_revision /*rev*/) noexcept
{
    return {3000, 32};
}

PrecompileAnalysis sha256_analyze(const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<60, 12>(input_size), 32};
}

inline constexpr PrecompileAnalysis ripemd160_analyze(
    const uint8_t* /*input*/, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<600, 120>(input_size), 32};
}

PrecompileAnalysis identity_analyze(
    const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<15, 3>(input_size), input_size};
}

PrecompileAnalysis ecadd_analyze(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 150 : 500, 64};
}

PrecompileAnalysis ecmul_analyze(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 6000 : 40000, 64};
}

PrecompileAnalysis ecpairing_analyze(const uint8_t*, size_t input_size, evmc_revision rev) noexcept
{
    const auto base_cost = (rev < EVMC_ISTANBUL) ? 100000 : 45000;
    const auto element_cost = (rev < EVMC_ISTANBUL) ? 80000 : 34000;
    const auto num_elements = static_cast<int64_t>(input_size / 192);
    return {base_cost + num_elements * element_cost, 32};
}

PrecompileAnalysis blake2bf_analyze(const uint8_t* input, size_t input_size, evmc_revision) noexcept
{
    return {input_size == 213 ? intx::be::unsafe::load<uint32_t>(input) : GasCostMax, 64};
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

PrecompileAnalysis internal_expmod_gas(
    const uint8_t* input_data, size_t input_size, evmc_revision rev) noexcept
{
    static constexpr size_t input_header_required_size = 3 * 32;
    const int64_t min_gas = rev < EVMC_BERLIN ? 0 : 200;

    uint8_t input_header[input_header_required_size]{};
    std::copy_n(input_data, std::min(input_size, input_header_required_size), input_header);

    const auto base_len256 = intx::be::unsafe::load<intx::uint256>(&input_header[0]);
    const auto exp_len256 = intx::be::unsafe::load<intx::uint256>(&input_header[32]);
    const auto mod_len256 = intx::be::unsafe::load<intx::uint256>(&input_header[64]);

    if (base_len256 == 0 && mod_len256 == 0)
    {
        return {min_gas, 0};
    }

    if (intx::count_significant_words(base_len256) > 1 ||
        intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1)
    {
        return {GasCostMax, 0};
    }

    const auto base_len64 = base_len256[0];
    const auto exp_len64 = exp_len256[0];

    bytes input;
    input.assign(input_data + sizeof(input_header),
        input_size < sizeof(input_header) ? 0 : (input_size - sizeof(input_header)));
    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64)
    {
        input.erase(0, static_cast<size_t>(base_len64));
        if (input.size() < 3 * 32)
            input.resize(3 * 32);
        if (exp_len64 < 32)
        {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
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
        return {GasCostMax, 0};
    }
    else
    {
        return {std::max(min_gas, static_cast<int64_t>(gas)), static_cast<size_t>(mod_len256)};
    }
}

ExecutionResult identity_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size == input_size);
    std::copy_n(input, input_size, output);
    return {EVMC_SUCCESS, input_size};
}

struct PrecompileTraits
{
    decltype(identity_analyze)* analyze = nullptr;
    decltype(identity_execute)* execute = nullptr;
};

template <PrecompileId Id>
ExecutionResult dummy_execute(const uint8_t*, size_t, uint8_t*, size_t) noexcept
{
    static constexpr auto impl = [](PrecompileId id) noexcept {
        std::cerr << "Precompile " << static_cast<int>(id) << " not implemented!\n";
        return ExecutionResult{EVMC_INTERNAL_ERROR, 0};
    };

    return impl(Id);
}

inline constexpr auto traits = []() noexcept {
    std::array<PrecompileTraits, 10> tbl{{
        {},  // undefined for 0
        {ecrecover_analyze, dummy_execute<PrecompileId::ecrecover>},
        {sha256_analyze, dummy_execute<PrecompileId::sha256>},
        {ripemd160_analyze, dummy_execute<PrecompileId::ripemd160>},
        {identity_analyze, identity_execute},
        {internal_expmod_gas, dummy_execute<PrecompileId::expmod>},
        {ecadd_analyze, dummy_execute<PrecompileId::ecadd>},
        {ecmul_analyze, dummy_execute<PrecompileId::ecmul>},
        {ecpairing_analyze, dummy_execute<PrecompileId::ecpairing>},
        {blake2bf_analyze, dummy_execute<PrecompileId::blake2bf>},
    }};
    return tbl;
}();
}  // namespace

std::optional<evmc::Result> call_precompile(evmc_revision rev, const evmc_message& msg) noexcept
{
    if (evmc::is_zero(msg.code_address) || msg.code_address > 0x09_address)
        return {};

    const auto id = msg.code_address.bytes[19];
    if (rev < EVMC_BYZANTIUM && id > 4)
        return {};

    if (rev < EVMC_ISTANBUL && id > 8)
        return {};

    assert(id > 0);
    assert(msg.gas >= 0);

    uint8_t output_buf[256];  // Big enough to handle all "expmod" tests.

    const auto t = traits[id];
    const auto [gas_cost, max_output_size] = t.analyze(msg.input_data, msg.input_size, rev);
    const auto gas_left = msg.gas - gas_cost;
    if (gas_left < 0)
        return evmc::Result{EVMC_OUT_OF_GAS};
    assert(std::size(output_buf) >= max_output_size);

    const bytes_view input{msg.input_data, msg.input_size};

    const auto [status_code, output_size] =
        t.execute(msg.input_data, msg.input_size, output_buf, max_output_size);

    evmc::Result result{
        status_code, status_code == EVMC_SUCCESS ? gas_left : 0, 0, output_buf, output_size};
    return result;
}
}  // namespace evmone::state
