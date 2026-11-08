// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "modarith.hpp"
#include <intx/intx.hpp>
#include <ranges>
#include <span>

namespace evmone::crypto
{
using namespace intx;

/// Compares two same-size little-endian word arrays as unsigned integers: returns true if x < y.
constexpr bool less(std::span<const uint64_t> x, std::span<const uint64_t> y) noexcept
{
    assert(x.size() == y.size());
    return std::ranges::lexicographical_compare(std::views::reverse(x), std::views::reverse(y));
}

/// Subtracts y from x: x[] -= y[]. The result is truncated to the size of x.
constexpr void sub(std::span<uint64_t> x, std::span<const uint64_t> y) noexcept
{
    assert(x.size() >= y.size());

    bool borrow = false;
    for (size_t i = 0; i < y.size(); ++i)
        std::tie(x[i], borrow) = subc(x[i], y[i], borrow);
    for (size_t i = y.size(); borrow && i < x.size(); ++i)
        std::tie(x[i], borrow) = subc(x[i], uint64_t{0}, borrow);
}

/// Multiplies multi-word x by single word y: r[] = x[] * y. Returns the carry word.
constexpr uint64_t mul(std::span<uint64_t> r, std::span<const uint64_t> x, uint64_t y) noexcept
{
    assert(r.size() == x.size());

    uint64_t c = 0;
#pragma GCC unroll 4
    for (size_t i = 0; i != x.size(); ++i)
        std::tie(c, r[i]) = addmul(0, x[i], y, c);
    return c;
}

/// Multiplies each word of x by y and adds the matching word of p, propagating a carry to the next
/// word. Starts with the initial carry c. Stores the result in r. Returns the final carry.
/// r[] = p[] + x[] * y (+ c).
constexpr uint64_t addmul(std::span<uint64_t> r, std::span<const uint64_t> p,
    std::span<const uint64_t> x, uint64_t y, uint64_t c = 0) noexcept
{
    assert(r.size() == p.size());
    assert(r.size() == x.size());

#pragma GCC unroll 4
    for (size_t i = 0; i != x.size(); ++i)
        std::tie(c, r[i]) = addmul(p[i], x[i], y, c);
    return c;
}

/// Performs the Almost Montgomery Multiplication (AMM) of n-word values for R = 2^(64n).
///
/// The AMM is a relaxed version of the Montgomery multiplication producing a result in Montgomery
/// form which is in range [0, R), i.e., it may be larger than the modulus.
/// This allows to skip the final conditional subtraction in most cases, improving performance.
///
/// For any x, y < R the reduction computes t = (x⋅y + q⋅mod) / R with q < R, so t < R + mod.
/// If t ≥ R, subtracting mod once brings it below R.
///
/// The inputs are expected to be in Montgomery form.
/// Additionally, passing y=1 converts x from Montgomery form back to plain form,
/// because for x = aR: mul_amm(x, 1) = aR⋅1⋅R⁻¹ % mod = a % mod.
///
/// See "Efficient Software Implementations of Modular Exponentiation":
/// https://eprint.iacr.org/2011/239.pdf
///
/// Computes r = x * y * R^-1 mod m for r, x, y and mod of n > 0 words. Requires odd mod with a
/// non-zero top word and mod⋅mod_inv ≡ -1 (mod 2⁶⁴). r must not alias x, y or mod.
EVMONE_PRESERVE_NONE void mul_amm_generic(uint64_t* r, const uint64_t* x, const uint64_t* y,
    const uint64_t* mod, uint64_t mod_inv, size_t n) noexcept;

#if defined(__x86_64__) || defined(__aarch64__)
/// Computes mul_amm_generic() with assembly, on x86-64 with the BMI2 and ADX instructions, which
/// the CPU must have.
EVMONE_PRESERVE_NONE void mul_amm_asm(uint64_t* r, const uint64_t* x, const uint64_t* y,
    const uint64_t* mod, uint64_t mod_inv, size_t n) noexcept;
#endif

/// Computes k ≥ 0 almost Montgomery squarings of x of 4 words: as many mul_amm_generic(r, x, x)
/// calls, each squaring the result of the previous. r may alias x.
EVMONE_PRESERVE_NONE void sqr_n_amm_256_generic(
    uint64_t* r, const uint64_t* x, size_t k, const uint64_t* mod, uint64_t mod_inv) noexcept;

#if defined(__x86_64__) || defined(__aarch64__)
/// Computes sqr_n_amm_256_generic() with assembly, on x86-64 with the BMI2 and ADX instructions,
/// which the CPU must have.
EVMONE_PRESERVE_NONE void sqr_n_amm_256_asm(
    uint64_t* r, const uint64_t* x, size_t k, const uint64_t* mod, uint64_t mod_inv) noexcept;
#endif

/// Computes mul_amm_generic(), with assembly on AArch64 and on x86-64 if the CPU has the BMI2 and
/// ADX instructions.
inline void mul_amm(uint64_t* r, const uint64_t* x, const uint64_t* y, const uint64_t* mod,
    uint64_t mod_inv, size_t n) noexcept
{
#ifdef __aarch64__
    mul_amm_asm(r, x, y, mod, mod_inv, n);
#else
#ifdef __x86_64__
    // The compilers move the check out of the loops of calls.
    if (cpu_has_adx)
        return mul_amm_asm(r, x, y, mod, mod_inv, n);
#endif
    mul_amm_generic(r, x, y, mod, mod_inv, n);
#endif
}

/// Computes sqr_n_amm_256_generic(), with assembly on AArch64 and on x86-64 if the CPU has the
/// BMI2 and ADX instructions.
inline void sqr_n_amm_256(
    uint64_t* r, const uint64_t* x, size_t k, const uint64_t* mod, uint64_t mod_inv) noexcept
{
#ifdef __aarch64__
    sqr_n_amm_256_asm(r, x, k, mod, mod_inv);
#else
#ifdef __x86_64__
    if (cpu_has_adx)
        return sqr_n_amm_256_asm(r, x, k, mod, mod_inv);
#endif
    sqr_n_amm_256_generic(r, x, k, mod, mod_inv);
#endif
}

}  // namespace evmone::crypto
