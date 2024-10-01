// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include "precompiles_internal.hpp"
#include "precompiles_stubs.hpp"
#include <evmone_precompiles/blake2b.hpp>
#include <evmone_precompiles/bls.hpp>
#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/ripemd160.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <evmone_precompiles/sha256.hpp>
#include <intx/intx.hpp>
#include <array>
#include <bit>
#include <cassert>
#include <limits>

#ifdef EVMONE_PRECOMPILES_SILKPRE
#include "precompiles_silkpre.hpp"
#endif

namespace evmone::state
{
using evmc::bytes;
using evmc::bytes_view;
using namespace evmc::literals;

namespace
{
constexpr auto GasCostMax = std::numeric_limits<int64_t>::max();

inline constexpr int64_t num_words(size_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + 31) / 32);
}

template <int BaseCost, int WordCost>
inline constexpr int64_t cost_per_input_word(size_t input_size) noexcept
{
    return BaseCost + WordCost * num_words(input_size);
}

int64_t bls_msm_cost(size_t k, int64_t multiplication_cost) noexcept
{
    assert(k > 0);

    static constexpr int64_t MULTIPLIER = 1000;
    static constexpr int16_t DISCOUNT[128] = {1200, 888, 764, 641, 594, 547, 500, 453, 438, 423,
        408, 394, 379, 364, 349, 334, 330, 326, 322, 318, 314, 310, 306, 302, 298, 294, 289, 285,
        281, 277, 273, 269, 268, 266, 265, 263, 262, 260, 259, 257, 256, 254, 253, 251, 250, 248,
        247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232, 231, 229, 228, 226, 225, 223, 222,
        221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213, 212, 211, 211, 210, 209, 208,
        208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199, 198, 197, 196, 196, 195,
        194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185, 184, 183, 182, 182,
        181, 180, 179, 179, 178, 177, 176, 176, 175, 174};

    const auto d = DISCOUNT[std::min(k, std::size(DISCOUNT)) - 1];
    return (static_cast<int64_t>(k) * multiplication_cost * d) / MULTIPLIER;
}

}  // namespace

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
        if (x <= 64)
            return x2;
        else if (x <= 1024)
            return (x2 >> 2) + 96 * x - 3072;
        else
            return (x2 >> 4) + 480 * x - 199680;
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

PrecompileAnalysis point_evaluation_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto POINT_EVALUATION_PRECOMPILE_GAS = 50000;
    return {POINT_EVALUATION_PRECOMPILE_GAS, 64};
}

PrecompileAnalysis bls12_g1add_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_G1ADD_PRECOMPILE_GAS = 500;
    return {BLS12_G1ADD_PRECOMPILE_GAS, 128};
}

PrecompileAnalysis bls12_g1mul_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_G1MUL_PRECOMPILE_GAS = 12000;
    return {BLS12_G1MUL_PRECOMPILE_GAS, 128};
}

PrecompileAnalysis bls12_g1msm_analyze(bytes_view input, evmc_revision) noexcept
{
    if (input.empty() || input.size() % 160 != 0)
        return {GasCostMax, 0};

    static constexpr auto BLS12_G1MUL_PRECOMPILE_GAS = 12000;
    return {bls_msm_cost(input.size() / 160, BLS12_G1MUL_PRECOMPILE_GAS), 128};
}

PrecompileAnalysis bls12_g2add_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_G2ADD_PRECOMPILE_GAS = 800;
    return {BLS12_G2ADD_PRECOMPILE_GAS, 256};
}

PrecompileAnalysis bls12_g2mul_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_G2MUL_PRECOMPILE_GAS = 45000;
    return {BLS12_G2MUL_PRECOMPILE_GAS, 256};
}

PrecompileAnalysis bls12_g2msm_analyze(bytes_view input, evmc_revision) noexcept
{
    if (input.empty() || input.size() % 288 != 0)
        return {GasCostMax, 0};

    static constexpr auto BLS12_G2MUL_PRECOMPILE_GAS = 45000;
    return {bls_msm_cost(input.size() / 288, BLS12_G2MUL_PRECOMPILE_GAS), 256};
}

PrecompileAnalysis bls12_pairing_check_analyze(bytes_view input, evmc_revision) noexcept
{
    static constexpr auto PAIR_SIZE = 384;

    if (input.empty() || input.size() % PAIR_SIZE != 0)
        return {GasCostMax, 0};

    const auto npairs = static_cast<int64_t>(input.size()) / PAIR_SIZE;

    static constexpr auto BLS12_PAIRING_CHECK_BASE_FEE_PRECOMPILE_GAS = 65000;
    static constexpr auto BLS12_PAIRING_CHECK_FEE_PRECOMPILE_GAS = 43000;
    return {BLS12_PAIRING_CHECK_BASE_FEE_PRECOMPILE_GAS +
                BLS12_PAIRING_CHECK_FEE_PRECOMPILE_GAS * npairs,
        32};
}

PrecompileAnalysis bls12_map_fp_to_g1_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_MAP_FP_TO_G1_PRECOMPILE_GAS = 5500;
    return {BLS12_MAP_FP_TO_G1_PRECOMPILE_GAS, 128};
}

PrecompileAnalysis bls12_map_fp2_to_g2_analyze(bytes_view, evmc_revision) noexcept
{
    static constexpr auto BLS12_MAP_FP2_TO_G2_PRECOMPILE_GAS = 75000;
    return {BLS12_MAP_FP2_TO_G2_PRECOMPILE_GAS, 256};
}

ExecutionResult ecrecover_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 32);

    uint8_t input_buffer[128]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));

    ethash::hash256 h{};
    std::memcpy(h.bytes, input_buffer, sizeof(h));

    const auto v = intx::be::unsafe::load<intx::uint256>(input_buffer + 32);
    if (v != 27 && v != 28)
        return {EVMC_SUCCESS, 0};
    const bool parity = v == 28;

    const auto r = intx::be::unsafe::load<intx::uint256>(input_buffer + 64);
    const auto s = intx::be::unsafe::load<intx::uint256>(input_buffer + 96);

    const auto res = evmmax::secp256k1::ecrecover(h, r, s, parity);
    if (res)
    {
        std::memset(output, 0, 12);
        std::memcpy(output + 12, res->bytes, 20);
        return {EVMC_SUCCESS, 32};
    }
    else
        return {EVMC_SUCCESS, 0};
}

ExecutionResult sha256_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 32);
    crypto::sha256(reinterpret_cast<std::byte*>(output), reinterpret_cast<const std::byte*>(input),
        input_size);
    return {EVMC_SUCCESS, 32};
}

ExecutionResult ripemd160_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 32);
    output = std::fill_n(output, 12, std::uint8_t{0});
    crypto::ripemd160(reinterpret_cast<std::byte*>(output),
        reinterpret_cast<const std::byte*>(input), input_size);
    return {EVMC_SUCCESS, 32};
}

ExecutionResult ecadd_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 64);

    uint8_t input_buffer[128]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));

    const evmmax::bn254::Point p = {intx::be::unsafe::load<intx::uint256>(input_buffer),
        intx::be::unsafe::load<intx::uint256>(input_buffer + 32)};
    const evmmax::bn254::Point q = {intx::be::unsafe::load<intx::uint256>(input_buffer + 64),
        intx::be::unsafe::load<intx::uint256>(input_buffer + 96)};

    if (evmmax::bn254::validate(p) && evmmax::bn254::validate(q))
    {
        const auto res = evmmax::bn254::add(p, q);
        intx::be::unsafe::store(output, res.x);
        intx::be::unsafe::store(output + 32, res.y);
        return {EVMC_SUCCESS, 64};
    }
    else
        return {EVMC_PRECOMPILE_FAILURE, 0};
}

ExecutionResult ecmul_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 64);

    uint8_t input_buffer[96]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));

    const evmmax::bn254::Point p = {intx::be::unsafe::load<intx::uint256>(input_buffer),
        intx::be::unsafe::load<intx::uint256>(input_buffer + 32)};
    const auto c = intx::be::unsafe::load<intx::uint256>(input_buffer + 64);

    if (evmmax::bn254::validate(p))
    {
        const auto res = evmmax::bn254::mul(p, c);
        intx::be::unsafe::store(output, res.x);
        intx::be::unsafe::store(output + 32, res.y);
        return {EVMC_SUCCESS, 64};
    }
    else
        return {EVMC_PRECOMPILE_FAILURE, 0};
}

ExecutionResult identity_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= input_size);
    std::copy_n(input, input_size, output);
    return {EVMC_SUCCESS, input_size};
}

ExecutionResult blake2bf_execute(const uint8_t* input, [[maybe_unused]] size_t input_size,
    uint8_t* output, [[maybe_unused]] size_t output_size) noexcept
{
    static_assert(std::endian::native == std::endian::little,
        "blake2bf only works correctly on little-endian architectures");
    assert(input_size >= 213);
    assert(output_size >= 64);

    const auto rounds = intx::be::unsafe::load<uint32_t>(input);
    input += sizeof(rounds);

    uint64_t h[8];
    std::memcpy(h, input, sizeof(h));
    input += sizeof(h);

    uint64_t m[16];
    std::memcpy(m, input, sizeof(m));
    input += sizeof(m);

    uint64_t t[2];
    std::memcpy(t, input, sizeof(t));
    input += sizeof(t);

    const auto f = *input;
    if (f != 0 && f != 1) [[unlikely]]
        return {EVMC_PRECOMPILE_FAILURE, 0};

    crypto::blake2b_compress(rounds, h, m, t, f != 0);
    std::memcpy(output, h, sizeof(h));
    return {EVMC_SUCCESS, sizeof(h)};
}

ExecutionResult ecpairing_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 32);

    const auto pair_size = 192;

    if (input_size % pair_size != 0)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    const auto pair_count = input_size / pair_size;

    if (pair_count > 0)
    {
        auto input_idx = input;

        std::vector<evmmax::bn254::Point> vG1(pair_count);
        std::vector<evmmax::bn254::ExtPoint> vG2(pair_count);

        for (size_t i = 0; i < pair_count; ++i)
        {
            const evmmax::bn254::Point p = {
                intx::be::unsafe::load<intx::uint256>(input_idx),
                intx::be::unsafe::load<intx::uint256>(input_idx + 32),
            };

            const evmmax::bn254::ExtPoint q = {
                {intx::be::unsafe::load<intx::uint256>(input_idx + 96),
                    intx::be::unsafe::load<intx::uint256>(input_idx + 64)},
                {intx::be::unsafe::load<intx::uint256>(input_idx + 160),
                    intx::be::unsafe::load<intx::uint256>(input_idx + 128)},
            };

            vG1[i] = p;
            vG2[i] = q;

            input_idx += pair_size;
        }

        const auto res = evmmax::bn254::pairing(vG2, vG1);

        if (res.has_value())
        {
            intx::be::unsafe::store(output, res.value() ? intx::uint256{1} : intx::uint256{0});
            return {EVMC_SUCCESS, 64};
        }
        else
            return {EVMC_PRECOMPILE_FAILURE, 0};
    }
    else
    {
        intx::be::unsafe::store(output, intx::uint256{1});
        return {EVMC_SUCCESS, 32};
    }
}


ExecutionResult point_evaluation_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size >= 64);
    if (input_size != 192)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    const auto r = crypto::kzg_verify_proof(reinterpret_cast<const std::byte*>(&input[0]),
        reinterpret_cast<const std::byte*>(&input[32]),
        reinterpret_cast<const std::byte*>(&input[64]),
        reinterpret_cast<const std::byte*>(&input[96]),
        reinterpret_cast<const std::byte*>(&input[96 + 48]));

    if (!r)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    // Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
    // as required by the EIP-4844.
    intx::be::unsafe::store(output, crypto::FIELD_ELEMENTS_PER_BLOB);
    intx::be::unsafe::store(output + 32, crypto::BLS_MODULUS);
    return {EVMC_SUCCESS, 64};
}

ExecutionResult bls12_g1add_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 256)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 128);

    if (!crypto::bls::g1_add(output, &output[64], input, &input[64], &input[128], &input[192]))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 128};
}

ExecutionResult bls12_g1mul_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 160)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 128);

    if (!crypto::bls::g1_mul(output, &output[64], input, &input[64], &input[128]))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 128};
}

ExecutionResult bls12_g1msm_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size % 160 != 0)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 128);

    if (!crypto::bls::g1_msm(output, &output[64], input, input_size))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 128};
}

ExecutionResult bls12_g2add_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 512)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 256);

    if (!crypto::bls::g2_add(output, &output[128], input, &input[128], &input[256], &input[384]))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 256};
}

ExecutionResult bls12_g2mul_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 288)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 256);

    if (!crypto::bls::g2_mul(output, &output[128], input, &input[128], &input[256]))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 256};
}

ExecutionResult bls12_g2msm_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size % 288 != 0)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 256);

    if (!crypto::bls::g2_msm(output, &output[128], input, input_size))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 256};
}

ExecutionResult bls12_pairing_check_execute(const uint8_t* input, size_t input_size,
    uint8_t* output, [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size % 384 != 0)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 32);

    if (!crypto::bls::pairing_check(output, input, input_size))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 32};
}

ExecutionResult bls12_map_fp_to_g1_execute(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 64)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 128);

    if (!crypto::bls::map_fp_to_g1(output, &output[64], input))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 128};
}

ExecutionResult bls12_map_fp2_to_g2_execute(const uint8_t* input, size_t input_size,
    uint8_t* output, [[maybe_unused]] size_t output_size) noexcept
{
    if (input_size != 128)
        return {EVMC_PRECOMPILE_FAILURE, 0};

    assert(output_size == 256);

    if (!crypto::bls::map_fp2_to_g2(output, &output[128], input))
        return {EVMC_PRECOMPILE_FAILURE, 0};

    return {EVMC_SUCCESS, 256};
}

namespace
{
struct PrecompileTraits
{
    decltype(identity_analyze)* analyze = nullptr;
    decltype(identity_execute)* execute = nullptr;
};

inline constexpr auto traits = []() noexcept {
    std::array<PrecompileTraits, NumPrecompiles> tbl{{
        {},  // undefined for 0
        {ecrecover_analyze, ecrecover_execute},
        {sha256_analyze, sha256_execute},
        {ripemd160_analyze, ripemd160_execute},
        {identity_analyze, identity_execute},
        {expmod_analyze, expmod_stub},
        {ecadd_analyze, ecadd_execute},
        {ecmul_analyze, ecmul_execute},
        {ecpairing_analyze, ecpairing_execute},
        {blake2bf_analyze, blake2bf_execute},
        {point_evaluation_analyze, point_evaluation_execute},
        {bls12_g1add_analyze, bls12_g1add_execute},
        {bls12_g1mul_analyze, bls12_g1mul_execute},
        {bls12_g1msm_analyze, bls12_g1msm_execute},
        {bls12_g2add_analyze, bls12_g2add_execute},
        {bls12_g2mul_analyze, bls12_g2mul_execute},
        {bls12_g2msm_analyze, bls12_g2msm_execute},
        {bls12_pairing_check_analyze, bls12_pairing_check_execute},
        {bls12_map_fp_to_g1_analyze, bls12_map_fp_to_g1_execute},
        {bls12_map_fp2_to_g2_analyze, bls12_map_fp2_to_g2_execute},
    }};
#ifdef EVMONE_PRECOMPILES_SILKPRE
    // tbl[static_cast<size_t>(PrecompileId::ecrecover)].execute = silkpre_ecrecover_execute;
    // tbl[static_cast<size_t>(PrecompileId::sha256)].execute = silkpre_sha256_execute;
    // tbl[static_cast<size_t>(PrecompileId::ripemd160)].execute = silkpre_ripemd160_execute;
    tbl[static_cast<size_t>(PrecompileId::expmod)].execute = silkpre_expmod_execute;
    // tbl[static_cast<size_t>(PrecompileId::ecadd)].execute = silkpre_ecadd_execute;
    // tbl[static_cast<size_t>(PrecompileId::ecmul)].execute = silkpre_ecmul_execute;
    // tbl[static_cast<size_t>(PrecompileId::blake2bf)].execute = silkpre_blake2bf_execute;
    // tbl[static_cast<size_t>(PrecompileId::ecpairing)].execute = silkpre_ecpairing_execute;
#endif
    return tbl;
}();
}  // namespace

bool is_precompile(evmc_revision rev, const evmc::address& addr) noexcept
{
    // Define compile-time constant,
    // TODO(clang18): workaround for Clang Analyzer bug, fixed in clang 18.
    //                https://github.com/llvm/llvm-project/issues/59493.
    static constexpr evmc::address address_boundary{stdx::to_underlying(PrecompileId::latest)};

    if (evmc::is_zero(addr) || addr > address_boundary)
        return false;

    const auto id = addr.bytes[19];
    if (rev < EVMC_BYZANTIUM && id >= stdx::to_underlying(PrecompileId::since_byzantium))
        return false;

    if (rev < EVMC_ISTANBUL && id >= stdx::to_underlying(PrecompileId::since_istanbul))
        return false;

    if (rev < EVMC_CANCUN && id >= stdx::to_underlying(PrecompileId::since_cancun))
        return false;

    if (rev < EVMC_PRAGUE && id >= stdx::to_underlying(PrecompileId::since_prague))
        return false;

    return true;
}

evmc::Result call_precompile(evmc_revision rev, const evmc_message& msg) noexcept
{
    assert(msg.gas >= 0);

    const auto id = msg.code_address.bytes[19];
    const auto [analyze, execute] = traits[id];

    const bytes_view input{msg.input_data, msg.input_size};
    const auto [gas_cost, max_output_size] = analyze(input, rev);
    const auto gas_left = msg.gas - gas_cost;
    if (gas_left < 0)
        return evmc::Result{EVMC_OUT_OF_GAS};

    // Allocate buffer for the precompile's output and pass its ownership to evmc::Result.
    // TODO: This can be done more elegantly by providing constructor evmc::Result(std::unique_ptr).
    const auto output_data = new (std::nothrow) uint8_t[max_output_size];
    const auto [status_code, output_size] =
        execute(msg.input_data, msg.input_size, output_data, max_output_size);
    const evmc_result result{status_code, status_code == EVMC_SUCCESS ? gas_left : 0, 0,
        output_data, output_size,
        [](const evmc_result* res) noexcept { delete[] res->output_data; }};
    return evmc::Result{result};
}
}  // namespace evmone::state
