// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>
#include <algorithm>
#include <bit>
#include <cassert>
#include <type_traits>
#include <utility>

namespace evmone::crypto
{
/// Computes the modular inverse of a modulo 2³², satisfying a⋅inv = 1 mod 2³².
/// Only odd arguments are invertible modulo a power of two.
constexpr uint32_t modinv_pow2(uint32_t a) noexcept
{
    assert(a % 2 == 1);  // The argument must be odd, otherwise the inverse does not exist.

    // Start with inversion mod 2⁴, which is a³ mod 2⁴ (for odd a).
    // All 8 cases can be verified manually, but the formal explanation can be found in:
    // https://en.wikipedia.org/wiki/Multiplicative_group_of_integers_modulo_n#Powers_of_2.
    // This is better tradeoff than a mod 2² plus one Newton-Raphson iteration.
    // We also avoid explicit mod 2⁴ because the top garbage bits are fine.
    auto inv = a * a * a;

    // Use the Newton–Raphson numeric method, see e.g.
    // https://gmplib.org/~tege/divcnst-pldi94.pdf#page=9, formula (9.2)
    // Each iteration doubles the number of correct bits, starting from 4:
    // 8, 16, 32, ..., so for 32-bit value we need 3 iterations.
    // TODO(C++23): static
    constexpr auto ITERATIONS = std::countr_zero(sizeof(a) * 8 / 4);
    for (auto i = 0; i < ITERATIONS; ++i)
        inv *= 2 - a * inv;  // Overflows are fine because they wrap around modulo 2³².

    assert(inv * a == 1);  // Verify the result.
    return inv;
}

/// Computes the modular inverse of a modulo 2⁶⁴, satisfying a⋅inv = 1 mod 2⁶⁴.
/// Only odd arguments are invertible modulo a power of two.
constexpr uint64_t modinv_pow2(uint64_t a) noexcept
{
    assert(a % 2 == 1);  // The argument must be odd, otherwise the inverse does not exist.
    uint64_t inv = modinv_pow2(static_cast<uint32_t>(a));  // Start with inversion mod 2³².
    inv *= 2 - a * inv;    // One Newton-Raphson iteration: 64 bits correct.
    assert(inv * a == 1);  // Verify the result.
    return inv;
}

/// Compute the modulus inverse for Montgomery multiplication, i.e., N': mod⋅N' = 2⁶⁴-1.
template <typename UintT>
constexpr uint64_t compute_mont_mod_inv(const UintT& mod) noexcept
{
    // Compute the inversion mod[0]⁻¹ mod 2⁶⁴, then the final result is N' = -mod[0]⁻¹
    // because this gives mod⋅N' = -1 mod 2⁶⁴ = 2⁶⁴-1.
    return -modinv_pow2(mod[0]);
}

/// Computes a⋅b + t + c, which always fits in 128 bits. Returns {high word, low word}.
constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    // TODO(GCC): The intx::uint128 sum is kept in a stack slot.
#if INTX_HAS_BUILTIN_INT128 && !defined(__clang__)
    const auto p = intx::builtin_uint128{a} * b + t + c;
    return {static_cast<uint64_t>(p >> 64), static_cast<uint64_t>(p)};
#else
    const auto p = intx::umul(a, b) + t + c;
    return {p[1], p[0]};
#endif
}

/// Performs a modular addition. Requires x < mod and y < mod.
template <typename UintT>
constexpr UintT modadd(const UintT& x, const UintT& y, const UintT& mod) noexcept
{
    assert(x < mod);
    assert(y < mod);
    const auto s = addc(x, y);  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
    const auto d = subc(s.value, mod);
    return (!s.carry && d.carry) ? s.value : d.value;
}

/// Performs a modular subtraction. Requires x < mod and y < mod.
template <typename UintT>
constexpr UintT modsub(const UintT& x, const UintT& y, const UintT& mod) noexcept
{
    assert(x < mod);
    assert(y < mod);
    const auto d = subc(x, y);
    const auto s = d.value + mod;
    return (d.carry) ? s : d.value;
}

// The building blocks of modinv_scaled(): the safegcd algorithm of D. J. Bernstein and B.-Y. Yang,
// "Fast constant-time gcd computation and modular inversion", IACR TCHES 2019(3),
// https://eprint.iacr.org/2019/266 (the section and theorem numbers refer to its 2019-04-13
// version). As in §12.1, batches of 62 divsteps run on the low words, and their transition matrix
// is then applied to the full values. The code departs from the paper's recip2 (§11) in:
// - Variable time: it stops once g = 0 instead of after the fixed number of divsteps of
//   Theorem 11.2.
// - A batch does the divsteps of all trailing zeros of g at once, and cancels the low k ≤ 5 bits
//   of g at once by adding w⋅f, w ≡ −g⋅f⁻¹ (mod 2ᵏ).
// - The inverse is the top-right entry vₙ of the product of the matrices, as in recip2, but each
//   batch's matrix updates the right column [vₙ, rₙ] modulo mod and divides it by 2⁶², instead of
//   a precomputed power of 1/2 at the end.
// - f and g drop their top word once it only extends the sign.
// - rₙ starts as scale, and non-invertible x gives 0.
// The first four follow libsecp256k1's modinv64_var (which cancels up to 6 bits after a swap and
// 4 bits otherwise), as does the correction that keeps vₙ and rₙ in (−2⋅mod, mod), and this code
// owes much to its explanation in
// https://github.com/bitcoin-core/secp256k1/blob/master/doc/safegcd_implementation.md.
namespace safegcd
{
/// The number of divsteps in a batch.
constexpr int BATCH = 62;

/// The transition matrix of a batch of divsteps scaled by 2ᴮᴬᵀᶜᴴ (§12.1):
/// [u v; q r]⋅[f, g] = 2ᴮᴬᵀᶜᴴ⋅[f', g'] for the f' and g' after the batch.
/// The row sums |u| + |v| and |q| + |r| are at most 2ᴮᴬᵀᶜᴴ.
struct TransitionMatrix
{
    int64_t u;
    int64_t v;
    int64_t q;
    int64_t r;
};

/// Computes a⋅b as a two's complement 128-bit value.
constexpr intx::uint128 mul_ss(int64_t a, int64_t b) noexcept
{
    auto p = intx::umul(static_cast<uint64_t>(a), static_cast<uint64_t>(b));
    p[1] -= (static_cast<uint64_t>(b) & static_cast<uint64_t>(a >> 63)) +
            (static_cast<uint64_t>(a) & static_cast<uint64_t>(b >> 63));
    return p;
}

/// Returns the low word of the 128-bit [hi, lo] shifted right by BATCH bits.
constexpr uint64_t shr_batch(uint64_t lo, uint64_t hi) noexcept
{
    return (lo >> BATCH) | (hi << (64 - BATCH));
}

/// Runs BATCH divsteps (§8) from delta and the f and g given by their low words, f odd.
/// Updates delta and returns the transition matrix of the batch.
constexpr TransitionMatrix divsteps(int64_t& delta, uint64_t f, uint64_t g) noexcept
{
    assert((f & 1) == 1);
    [[maybe_unused]] const auto f0 = f;
    [[maybe_unused]] const auto g0 = g;

    // The matrix of the divsteps so far, scaled by 2ⁱ after i of them:
    // u⋅f₀ + v⋅g₀ = 2ⁱ⋅f and q⋅f₀ + r⋅g₀ = 2ⁱ⋅g modulo 2⁶⁴.
    uint64_t u = 1;
    uint64_t v = 0;
    uint64_t q = 0;
    uint64_t r = 1;
    int left = BATCH;
    while (true)
    {
        // While g is even, a divstep is (δ, f, g) → (1 + δ, f, g/2).
        const auto zeros = std::countr_zero(g | (~uint64_t{0} << left));
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        delta += zeros;
        left -= zeros;
        if (left == 0)
            break;

        // For odd g, a divstep is the conditional swap (δ, f, g) → (−δ, g, −f) if δ > 0,
        // followed by the elimination (δ, f, g) → (1 + δ, f, (g + f)/2) (§8.2).
        // neg_g is −g, kept apart to take the negation off the critical path.
        auto neg_g = -g;
        if (delta > 0)
        {
            delta = -delta;
            neg_g = f;
            f = g;
            g = -neg_g;
            std::swap(u, q);
            std::swap(v, r);
            q = -q;
            r = -r;
        }

        // Now δ ≤ 0, so the next 1 − δ divsteps are eliminations, also those for even g.
        // The first k = min(1 − δ, left, 5) of them add w⋅f to g, for w ≡ −g⋅f⁻¹ (mod 2ᵏ),
        // which gives g k trailing zeros for the shift above. f⁻¹ ≡ (3⋅f) ⊕ 2 (mod 2⁵), as the
        // 16 odd residues show, so w takes a single multiplication.
        const auto mask = ~(~uint64_t{0} << std::min<int64_t>(1 - delta, left)) & 31;
        const auto w = (neg_g * ((3 * f) ^ 2)) & mask;
        g += w * f;
        assert((g & mask) == 0);
        q += w * u;
        r += w * v;
    }
    assert(u * f0 + v * g0 == f << BATCH);
    assert(q * f0 + r * g0 == g << BATCH);
    const TransitionMatrix t{static_cast<int64_t>(u), static_cast<int64_t>(v),
        static_cast<int64_t>(q), static_cast<int64_t>(r)};
    // The matrices T(δ, f, g) of §8.1 have determinant 1/2,
    // so the matrix 2ᴮᴬᵀᶜᴴ⋅T⋯T of the batch has determinant 2ᴮᴬᵀᶜᴴ.
    assert(mul_ss(t.u, t.r) - mul_ss(t.v, t.q) == intx::uint128{1} << BATCH);
    // TODO(C++23): Use std::abs.
    [[maybe_unused]] constexpr auto abs = [](int64_t a) { return a < 0 ? -a : a; };
    assert(abs(t.u) <= (int64_t{1} << BATCH) - abs(t.v));
    assert(abs(t.q) <= (int64_t{1} << BATCH) - abs(t.r));
    return t;
}

/// A coefficient a as its magnitude |a| and its sign mask s, all ones for negative a,
/// for a⋅x = |a|⋅(x ⊕ s) + (|a| & s), which holds as −x = ~x + 1.
struct Coef
{
    // With the identity, the products of the low words of x in two's complement are unsigned.
    uint64_t mag;
    uint64_t sign;

    constexpr explicit Coef(int64_t a) noexcept
      : mag{static_cast<uint64_t>(a < 0 ? -a : a)}, sign{static_cast<uint64_t>(a >> 63)}
    {}

    [[nodiscard]] constexpr uint64_t bias() const noexcept { return mag & sign; }
};

/// Computes [f, g] = t⋅[f, g] / 2ᴮᴬᵀᶜᴴ for f and g of len words and the matrix t of the divsteps
/// from their low words, which makes the division exact and the results fit in len words (§8.3).
/// The words from len on are neither read nor written.
template <typename SignedT>
[[gnu::always_inline]] constexpr void update_fg(
    size_t len, SignedT& f, SignedT& g, const TransitionMatrix& t) noexcept
{
    const Coef u{t.u};
    const Coef v{t.v};
    const Coef q{t.q};
    const Coef r{t.r};
    // The carries into the next word, and the low words of the previous sums.
    auto carry_f = u.bias() + v.bias();
    auto carry_g = q.bias() + r.bias();
    uint64_t prev_f = 0;
    uint64_t prev_g = 0;
    for (size_t i = 0; i < len - 1; ++i)
    {
        const auto fi = f[i];
        const auto gi = g[i];
        const auto [h1, l1] = addmul(carry_f, u.mag, fi ^ u.sign, 0);
        const auto [h2, l2] = addmul(l1, v.mag, gi ^ v.sign, 0);
        const auto [h3, l3] = addmul(carry_g, q.mag, fi ^ q.sign, 0);
        const auto [h4, l4] = addmul(l3, r.mag, gi ^ r.sign, 0);
        if (i != 0)
        {
            f[i - 1] = shr_batch(prev_f, l2);
            g[i - 1] = shr_batch(prev_g, l4);
        }
        prev_f = l2;
        prev_g = l4;
        carry_f = h1 + h2;
        carry_g = h3 + h4;
    }
    const auto f_top = f[len - 1];
    const auto g_top = g[len - 1];
    const auto sum_f = mul_ss(static_cast<int64_t>(u.mag), static_cast<int64_t>(f_top ^ u.sign)) +
                       mul_ss(static_cast<int64_t>(v.mag), static_cast<int64_t>(g_top ^ v.sign)) +
                       intx::uint128{carry_f};
    const auto sum_g = mul_ss(static_cast<int64_t>(q.mag), static_cast<int64_t>(f_top ^ q.sign)) +
                       mul_ss(static_cast<int64_t>(r.mag), static_cast<int64_t>(g_top ^ r.sign)) +
                       intx::uint128{carry_g};
    // f and g stay in [-2ⁿ, 2ⁿ) for n = 64⋅len - 1 (§8.3), so the results fit in len words.
    assert(static_cast<int64_t>(sum_f[1]) >> (BATCH - 1) == static_cast<int64_t>(sum_f[1]) >> 63);
    assert(static_cast<int64_t>(sum_g[1]) >> (BATCH - 1) == static_cast<int64_t>(sum_g[1]) >> 63);
    if (len != 1)
    {
        f[len - 2] = shr_batch(prev_f, sum_f[0]);
        g[len - 2] = shr_batch(prev_g, sum_g[0]);
    }
    f[len - 1] = shr_batch(sum_f[0], sum_f[1]);
    g[len - 1] = shr_batch(sum_g[0], sum_g[1]);
}

/// Computes [vn, rn] = (t⋅[vn, rn] + mod⋅[mv, mr]) / 2ᴮᴬᵀᶜᴴ, with mv and mr making the division
/// exact. Requires vn and rn in (−2⋅mod, mod), the row sums of t at most 2ᴮᴬᵀᶜᴴ, and
/// mod_inv⋅mod ≡ 1 (mod 2⁶⁴). The results are in (−2⋅mod, mod).
template <typename SignedT, typename UintT>
[[gnu::always_inline]] constexpr void update_vr(SignedT& vn, SignedT& rn, const TransitionMatrix& t,
    const UintT& mod, uint64_t mod_inv) noexcept
{
    constexpr auto TOP = UintT::num_words;
    constexpr uint64_t MASK = (uint64_t{1} << BATCH) - 1;
    static_assert(SignedT::num_words == TOP + 1);
    const Coef u{t.u};
    const Coef v{t.v};
    const Coef q{t.q};
    const Coef r{t.r};

    // Counting negative vn or rn as itself plus mod keeps |u⋅vn + v⋅rn| < 2ᴮᴬᵀᶜᴴ⋅mod,
    // then subtracting less than 2ᴮᴬᵀᶜᴴ more multiples of mod makes the division exact
    // and puts the result in (−2⋅mod, mod).
    const auto vn_sign = static_cast<int64_t>(vn[TOP]) >> 63;
    const auto rn_sign = static_cast<int64_t>(rn[TOP]) >> 63;
    const auto fold_v = (t.u & vn_sign) + (t.v & rn_sign);
    const auto fold_r = (t.q & vn_sign) + (t.r & rn_sign);
    const auto vn0 = vn[0];
    const auto rn0 = rn[0];
    const auto [h1, l1] = addmul(u.bias() + v.bias(), u.mag, vn0 ^ u.sign, 0);
    const auto [h2, l2] = addmul(l1, v.mag, rn0 ^ v.sign, 0);
    const auto [h3, l3] = addmul(q.bias() + r.bias(), q.mag, vn0 ^ q.sign, 0);
    const auto [h4, l4] = addmul(l3, r.mag, rn0 ^ r.sign, 0);
    // mv is the fold, at most |u| + |v| ≤ 2ᴮᴬᵀᶜᴴ in magnitude, less up to 2ᴮᴬᵀᶜᴴ − 1, so
    // |u| + |v| + |mv| < 3⋅2ᴮᴬᵀᶜᴴ < 2⁶⁴ and the word sums below fit in 128 bits.
    static_assert((uint64_t{3} << BATCH) >> BATCH == 3);
    const Coef mv{
        fold_v - static_cast<int64_t>((mod_inv * l2 + static_cast<uint64_t>(fold_v)) & MASK)};
    const Coef mr{
        fold_r - static_cast<int64_t>((mod_inv * l4 + static_cast<uint64_t>(fold_r)) & MASK)};
    const auto [h5, l5] = addmul(l2, mv.mag, mod[0] ^ mv.sign, mv.bias());
    const auto [h6, l6] = addmul(l4, mr.mag, mod[0] ^ mr.sign, mr.bias());
    assert((l5 & MASK) == 0);
    assert((l6 & MASK) == 0);
    auto prev_v = l5;
    auto prev_r = l6;
    auto carry_v = h1 + h2 + h5;
    auto carry_r = h3 + h4 + h6;
    for (size_t i = 1; i < TOP; ++i)
    {
        const auto vni = vn[i];
        const auto rni = rn[i];
        const auto [g1, k1] = addmul(carry_v, u.mag, vni ^ u.sign, 0);
        const auto [g2, k2] = addmul(k1, v.mag, rni ^ v.sign, 0);
        const auto [g3, k3] = addmul(k2, mv.mag, mod[i] ^ mv.sign, 0);
        const auto [g4, k4] = addmul(carry_r, q.mag, vni ^ q.sign, 0);
        const auto [g5, k5] = addmul(k4, r.mag, rni ^ r.sign, 0);
        const auto [g6, k6] = addmul(k5, mr.mag, mod[i] ^ mr.sign, 0);
        vn[i - 1] = shr_batch(prev_v, k3);
        rn[i - 1] = shr_batch(prev_r, k6);
        prev_v = k3;
        prev_r = k6;
        carry_v = g1 + g2 + g3;
        carry_r = g4 + g5 + g6;
    }
    // The top words of vn and rn are in [−2, 0] and |u| + |v| ≤ 2ᴮᴬᵀᶜᴴ, so these sums fit in
    // int64. The top word of mod is 0, so its term is only −(|mv| & s).
    const auto vn_top = vn[TOP];
    const auto rn_top = rn[TOP];
    assert(static_cast<int64_t>(vn_top) >= -2 && static_cast<int64_t>(vn_top) <= 0);
    assert(static_cast<int64_t>(rn_top) >= -2 && static_cast<int64_t>(rn_top) <= 0);
    const auto top_v = static_cast<int64_t>(u.mag) * static_cast<int64_t>(vn_top ^ u.sign) +
                       static_cast<int64_t>(v.mag) * static_cast<int64_t>(rn_top ^ v.sign);
    const auto top_r = static_cast<int64_t>(q.mag) * static_cast<int64_t>(vn_top ^ q.sign) +
                       static_cast<int64_t>(r.mag) * static_cast<int64_t>(rn_top ^ r.sign);
    const auto sum_v =
        intx::uint128{carry_v} - intx::uint128{mv.bias()} +
        intx::uint128{static_cast<uint64_t>(top_v), static_cast<uint64_t>(top_v >> 63)};
    const auto sum_r =
        intx::uint128{carry_r} - intx::uint128{mr.bias()} +
        intx::uint128{static_cast<uint64_t>(top_r), static_cast<uint64_t>(top_r >> 63)};
    vn[TOP - 1] = shr_batch(prev_v, sum_v[0]);
    rn[TOP - 1] = shr_batch(prev_r, sum_r[0]);
    vn[TOP] = shr_batch(sum_v[0], sum_v[1]);
    rn[TOP] = shr_batch(sum_r[0], sum_r[1]);
}

template <typename UintT>
constexpr UintT modinv_scaled(const UintT& x, const UintT& scale, const UintT& mod) noexcept
{
    assert((mod & 1) == 1);
    assert(mod >= 3);
    assert(x < mod);
    assert(scale < mod);  // Otherwise rn starts out of its range.

    using SignedT = intx::uint<UintT::num_bits + 64>;
    const SignedT signed_mod = mod;
    const auto mod_inv = modinv_pow2(mod[0]);

    // (δ, f, g) = divstepⁿ(1, mod, x) as in Theorem 11.2, with vn and rn, the right column of the
    // product of the transition matrices, kept modulo mod and times scale:
    // vn⋅x ≡ scale⋅f and rn⋅x ≡ scale⋅g (mod mod).
    int64_t delta = 1;
    SignedT f = mod;
    SignedT g = x;
    SignedT vn = 0;
    SignedT rn = scale;
    size_t len = SignedT::num_words;  // The words of f and g in use, the higher words are stale.

    // For b-bit f and g, b ≥ 46, g = 0 after ⌊(49⋅b + 57)/17⌋ divsteps (Theorem 11.2).
    [[maybe_unused]] constexpr auto MAX_DIVSTEPS = (49 * UintT::num_bits + 57) / 17;
    [[maybe_unused]] unsigned num_divsteps = 0;
    while (true)
    {
        assert(num_divsteps < MAX_DIVSTEPS);
        num_divsteps += BATCH;
        const auto t = divsteps(delta, f[0], g[0]);
        update_fg(len, f, g, t);
        update_vr(vn, rn, t, mod, mod_inv);
        assert(intx::slt(-(2 * signed_mod), vn) && intx::slt(vn, signed_mod));
        assert(intx::slt(-(2 * signed_mod), rn) && intx::slt(rn, signed_mod));

        uint64_t g_any = 0;
        for (size_t i = 0; i < len; ++i)
            g_any |= g[i];
        if (g_any == 0)
            break;

        // Drop the top word if it only extends the sign of the word below.
        if (len >= 2)
        {
            const auto f_ext = static_cast<uint64_t>(static_cast<int64_t>(f[len - 2]) >> 63);
            const auto g_ext = static_cast<uint64_t>(static_cast<int64_t>(g[len - 2]) >> 63);
            if (((f[len - 1] ^ f_ext) | (g[len - 1] ^ g_ext)) == 0)
                --len;
        }
    }

    // Now f = ±gcd(x, mod), and vn ≡ ±scale⋅x⁻¹ (mod mod) if the gcd is 1.
    const auto f_sign = static_cast<uint64_t>(static_cast<int64_t>(f[len - 1]) >> 63);
    if (f[0] != (f_sign | 1))
        return 0;
    for (size_t i = 1; i < len; ++i)
    {
        if (f[i] != f_sign)
            return 0;
    }

    // Move vn from (−2⋅mod, mod) to [0, mod), negated if f = −1.
    if (static_cast<int64_t>(vn[SignedT::num_words - 1]) < 0)
        vn += signed_mod;
    if (f_sign != 0)
        vn = -vn;
    if (static_cast<int64_t>(vn[SignedT::num_words - 1]) < 0)
        vn += signed_mod;
    assert(vn < signed_mod);
    return static_cast<UintT>(vn);
}

extern template intx::uint256 modinv_scaled(
    const intx::uint256& x, const intx::uint256& scale, const intx::uint256& mod) noexcept;
extern template intx::uint384 modinv_scaled(
    const intx::uint384& x, const intx::uint384& scale, const intx::uint384& mod) noexcept;

/// The runtime modinv_scaled(), defined in modarith.cpp for intx::uint256 and intx::uint384.
template <typename UintT>
UintT modinv_scaled_rt(const UintT& x, const UintT& scale, const UintT& mod) noexcept;
}  // namespace safegcd

/// Computes scale⋅x⁻¹ % mod, i.e. the modular inverse of x scaled by the given factor.
/// Returns 0 for non-invertible x (including x == 0).
/// Requires an odd mod not less than 3, and both x and scale less than mod.
/// Runs in variable time. At runtime, defined for intx::uint256 and intx::uint384.
template <typename UintT>
constexpr UintT modinv_scaled(const UintT& x, const UintT& scale, const UintT& mod) noexcept
{
    if (std::is_constant_evaluated())
        return safegcd::modinv_scaled(x, scale, mod);
    return safegcd::modinv_scaled_rt(x, scale, mod);
}

/// The modular arithmetic operations using the Montgomery form of the values.
template <typename UintT>
class ModArith
{
    const UintT mod_;  ///< The modulus.

    const UintT r_squared_;  ///< R² % mod.

    /// The modulus inversion, i.e. the number N' such that mod⋅N' = 2⁶⁴-1.
    const uint64_t mod_inv_;

    /// Compute R² % mod.
    static constexpr UintT compute_r_squared(const UintT& mod) noexcept
    {
        // R is 2^num_bits, R² is 2^(2*num_bits) and needs 2*num_bits+1 bits to represent,
        // rounded to 2*num_bits+64 for intx requirements.
        constexpr auto RR = intx::uint<UintT::num_bits * 2 + 64>{1} << (UintT::num_bits * 2);
        return intx::udivrem(RR, mod).rem;
    }

public:
    constexpr explicit ModArith(const UintT& mod) noexcept
      : mod_{mod}, r_squared_{compute_r_squared(mod)}, mod_inv_{compute_mont_mod_inv(mod)}
    {}

    /// Returns the modulus.
    constexpr const UintT& mod() const noexcept { return mod_; }

    /// Converts a value to Montgomery form.
    ///
    /// This is done by using Montgomery multiplication mul(x, R²)
    /// what gives aR²R⁻¹ % mod = aR % mod.
    constexpr UintT to_mont(const UintT& x) const noexcept { return mul(x, r_squared_); }

    /// Converts a value in Montgomery form back to normal value.
    ///
    /// Given the x is the Montgomery form x = aR, the conversion is done by using
    /// Montgomery multiplication mul(x, 1) what gives aRR⁻¹ % mod = a % mod.
    constexpr UintT from_mont(const UintT& x) const noexcept { return mul(x, 1); }

    /// Performs a Montgomery modular multiplication.
    ///
    /// Inputs must be in Montgomery form: x = aR, y = bR.
    /// This computes Montgomery multiplication xyR⁻¹ % mod what gives aRbRR⁻¹ % mod = abR % mod.
    /// The result (abR) is in Montgomery form.
    constexpr UintT mul(const UintT& x, const UintT& y) const noexcept
    {
        // Coarsely Integrated Operand Scanning (CIOS) Method
        // Based on 2.3.2 from
        // High-Speed Algorithms & Architectures For Number-Theoretic Cryptosystems
        // https://www.microsoft.com/en-us/research/wp-content/uploads/1998/06/97Acar.pdf

        constexpr auto S = UintT::num_words;  // TODO(C++23): Make it static

        intx::uint<UintT::num_bits + 64> t;
        for (size_t i = 0; i != S; ++i)
        {
            uint64_t c = 0;
#pragma GCC unroll 8
            for (size_t j = 0; j != S; ++j)
                std::tie(c, t[j]) = addmul(t[j], x[j], y[i], c);
            auto tmp = intx::addc(t[S], c);
            t[S] = tmp.value;
            const auto d = tmp.carry;  // TODO: Carry is 0 for sparse modulus.

            const auto m = t[0] * mod_inv_;
            std::tie(c, std::ignore) = addmul(t[0], m, mod_[0], 0);
#pragma GCC unroll 8
            for (size_t j = 1; j != S; ++j)
                std::tie(c, t[j - 1]) = addmul(t[j], m, mod_[j], c);
            tmp = intx::addc(t[S], c);
            t[S - 1] = tmp.value;
            t[S] = d + tmp.carry;  // TODO: Carry is 0 for sparse modulus.
        }

        if (t >= mod_)
            t -= mod_;

        return static_cast<UintT>(t);
    }

    /// Performs a modular addition.
    constexpr UintT add(const UintT& x, const UintT& y) const noexcept
    {
        // Using generic procedure is fine for Montgomery forms.
        return modadd(x, y, mod_);
    }

    /// Performs a modular subtraction.
    constexpr UintT sub(const UintT& x, const UintT& y) const noexcept
    {
        // Using generic procedure is fine for Montgomery forms.
        return modsub(x, y, mod_);
    }

    /// Computes modular inverse of x in Montgomery form. Result is in Montgomery form.
    /// Returns 0 for non-invertible x (including x == 0).
    constexpr UintT inv(const UintT& x) const noexcept
    {
        // The input XR would invert to X⁻¹R⁻¹, so scaling by R² gives the expected Montgomery
        // form X⁻¹R at no extra cost.
        return modinv_scaled(x, r_squared_, mod_);
    }
};
}  // namespace evmone::crypto
