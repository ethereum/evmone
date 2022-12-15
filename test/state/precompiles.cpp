// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include "precompiles_cache.hpp"
#include <intx/intx.hpp>
#include <bit>
#include <cassert>
#include <iostream>
#include <limits>
#include <unordered_map>

namespace evmone::state
{
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

PrecompileAnalysis ecrecover_analyze(bytes_view /*input*/, evmc_revision /*rev*/) noexcept
{
    return {3000, 32};
}

PrecompileAnalysis sha256_analyze(bytes_view input, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<60, 12>(input.size()), 32};
}

PrecompileAnalysis ripemd160_analyze(bytes_view input, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<600, 120>(input.size()), 32};
}

PrecompileAnalysis identity_analyze(bytes_view input, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<15, 3>(input.size()), input.size()};
}

PrecompileAnalysis ecadd_analyze(bytes_view /*input*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 150 : 500, 64};
}

PrecompileAnalysis ecmul_analyze(bytes_view /*input*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 6000 : 40000, 64};
}

PrecompileAnalysis ecpairing_analyze(bytes_view input, evmc_revision rev) noexcept
{
    const auto base_cost = (rev >= EVMC_ISTANBUL) ? 45000 : 100000;
    const auto element_cost = (rev >= EVMC_ISTANBUL) ? 34000 : 80000;
    const auto num_elements = static_cast<int64_t>(input.size() / 192);
    return {base_cost + num_elements * element_cost, 32};
}

PrecompileAnalysis blake2bf_analyze(bytes_view input, evmc_revision) noexcept
{
    return {input.size() == 213 ? intx::be::unsafe::load<uint32_t>(input.data()) : GasCostMax, 64};
}

PrecompileAnalysis expmod_analyze(bytes_view input, evmc_revision rev) noexcept
{
    using namespace intx;

    static constexpr size_t input_header_required_size = 3 * sizeof(uint256);
    const int64_t min_gas = (rev >= EVMC_BERLIN) ? 200 : 0;

    uint8_t input_header[input_header_required_size]{};
    std::copy_n(input.data(), std::min(input.size(), input_header_required_size), input_header);

    const auto base_len = be::unsafe::load<uint256>(&input_header[0]);
    const auto exp_len = be::unsafe::load<uint256>(&input_header[32]);
    const auto mod_len = be::unsafe::load<uint256>(&input_header[64]);

    if (base_len == 0 && mod_len == 0)
        return {min_gas, 0};

    static constexpr auto len_limit = std::numeric_limits<size_t>::max();
    if (base_len > len_limit || exp_len > len_limit || mod_len > len_limit)
        return {GasCostMax, 0};

    auto adjusted_len = [input](size_t offset, size_t len) {
        const auto head_len = std::min(len, size_t{32});
        const auto head_explicit_len =
            std::max(std::min(offset + head_len, input.size()), offset) - offset;
        const bytes_view head_explicit_bytes(&input[offset], head_explicit_len);
        const auto top_byte_index = head_explicit_bytes.find_first_not_of(uint8_t{0});
        const size_t exp_bit_width =
            (top_byte_index != bytes_view::npos) ?
                (head_len - top_byte_index - 1) * 8 +
                    static_cast<size_t>(std::bit_width(head_explicit_bytes[top_byte_index])) :
                0;

        return std::max(
            8 * (std::max(len, size_t{32}) - 32) + (std::max(exp_bit_width, size_t{1}) - 1),
            size_t{1});
    };

    static constexpr auto mult_complexity_eip2565 = [](const uint256& x) noexcept {
        const auto w = (x + 7) >> 3;
        return w * w;
    };
    static constexpr auto mult_complexity_eip198 = [](const uint256& x) noexcept {
        const auto x2 = x * x;
        return (x <= 64)   ? x2 :
               (x <= 1024) ? (x2 >> 2) + 96 * x - 3072 :
                             (x2 >> 4) + 480 * x - 199680;
    };

    const auto max_len = std::max(mod_len, base_len);
    const auto adjusted_exp_len = adjusted_len(
        sizeof(input_header) + static_cast<size_t>(base_len), static_cast<size_t>(exp_len));
    const auto gas = (rev >= EVMC_BERLIN) ?
                         mult_complexity_eip2565(max_len) * adjusted_exp_len / 3 :
                         mult_complexity_eip198(max_len) * adjusted_exp_len / 20;
    return {std::max(min_gas, static_cast<int64_t>(std::min(gas, intx::uint256{GasCostMax}))),
        static_cast<size_t>(mod_len)};
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
    std::cerr << "Precompile " << static_cast<int>(Id) << " not implemented!\n";
    return ExecutionResult{EVMC_INTERNAL_ERROR, 0};
}

inline constexpr auto traits = []() noexcept {
    std::array<PrecompileTraits, NumPrecompiles> tbl{{
        {},  // undefined for 0
        {ecrecover_analyze, dummy_execute<PrecompileId::ecrecover>},
        {sha256_analyze, dummy_execute<PrecompileId::sha256>},
        {ripemd160_analyze, dummy_execute<PrecompileId::ripemd160>},
        {identity_analyze, identity_execute},
        {expmod_analyze, dummy_execute<PrecompileId::expmod>},
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
    // Define compile-time constant,
    // TODO: workaround for Clang Analyzer bug https://github.com/llvm/llvm-project/issues/59493.
    static constexpr evmc::address address_boundary{NumPrecompiles};

    if (evmc::is_zero(msg.code_address) || msg.code_address >= address_boundary)
        return {};

    const auto id = msg.code_address.bytes[19];
    if (rev < EVMC_BYZANTIUM && id > 4)
        return {};

    if (rev < EVMC_ISTANBUL && id > 8)
        return {};

    assert(id > 0);
    assert(msg.gas >= 0);

    const auto [analyze, execute] = traits[id];

    const bytes_view input{msg.input_data, msg.input_size};
    const auto [gas_cost, max_output_size] = analyze(input, rev);
    const auto gas_left = msg.gas - gas_cost;
    if (gas_left < 0)
        return evmc::Result{EVMC_OUT_OF_GAS};

    static Cache cache;
    if (auto r = cache.find(static_cast<PrecompileId>(id), input, gas_left); r.has_value())
        return r;

    uint8_t output_buf[256];  // Big enough to handle all "expmod" tests.
    assert(std::size(output_buf) >= max_output_size);

    const auto [status_code, output_size] =
        execute(msg.input_data, msg.input_size, output_buf, max_output_size);

    evmc::Result result{
        status_code, status_code == EVMC_SUCCESS ? gas_left : 0, 0, output_buf, output_size};

    cache.insert(static_cast<PrecompileId>(id), input, result);

    return result;
}
}  // namespace evmone::state
