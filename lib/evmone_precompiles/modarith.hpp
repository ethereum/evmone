// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>
#include <algorithm>
#include <bit>
#include <cassert>
#include <type_traits>

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

// The x86-64 Montgomery multiplication kernels use all registers: let the callers save only the
// registers they need.
#ifdef __x86_64__
#if __has_attribute(preserve_none)
#define EVMONE_PRESERVE_NONE __attribute__((preserve_none))
#endif
#endif
#ifndef EVMONE_PRESERVE_NONE
#define EVMONE_PRESERVE_NONE
#endif

#ifdef __x86_64__
#if defined(__BMI2__) && defined(__ADX__)
inline constexpr bool cpu_has_adx = true;
#else
/// Whether the CPU has the BMI2 and ADX instructions, set at the program start (false until then).
[[gnu::visibility("hidden")]] extern const bool cpu_has_adx;
#endif

/// Computes the Montgomery product x⋅y⋅2⁻²⁵⁶ % m with portable code.
/// Requires odd m, x < m, y < m and m⋅m_inv ≡ -1 (mod 2⁶⁴). The result is less than m.
EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_generic(const intx::uint256& x,
    const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept;

// The kernels below compute mul_mont_256_generic() with the BMI2 and ADX instructions if the CPU
// has them: the program start sets them, they run mul_mont_256_generic() until then.

/// The Montgomery multiplication kernel for any m.
[[gnu::visibility("hidden")]] extern decltype(&mul_mont_256_generic) mul_mont_256;

/// The Montgomery multiplication kernel for m < 2²⁵⁵.
[[gnu::visibility("hidden")]] extern decltype(&mul_mont_256_generic) mul_mont_256_sparse;

/// The Montgomery multiplication kernel for the pseudo-Mersenne m = 2²⁵⁶ - c, c < 2⁶⁴.
[[gnu::visibility("hidden")]] extern decltype(&mul_mont_256_generic) mul_mont_256_pm;

/// The P-256 field prime 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1.
inline constexpr intx::uint256 P256_FIELD_PRIME{
    0xffffffffffffffff, 0x00000000ffffffff, 0, 0xffffffff00000001};

/// The Montgomery multiplication kernel for m = P256_FIELD_PRIME.
[[gnu::visibility("hidden")]] extern decltype(&mul_mont_256_generic) mul_mont_256_p256;
#endif

/// Computes the Montgomery product x⋅y⋅R⁻¹ % mod for R = 2^(64⋅N) of N-word UintT, portably.
/// Requires odd mod, x < mod, y < mod and mod⋅mod_inv ≡ -1 (mod 2⁶⁴). The result is less than mod.
template <typename UintT>
constexpr UintT mul_mont_generic(
    const UintT& x, const UintT& y, const UintT& mod, uint64_t mod_inv) noexcept
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

        const auto m = t[0] * mod_inv;
        std::tie(c, std::ignore) = addmul(t[0], m, mod[0], 0);
#pragma GCC unroll 8
        for (size_t j = 1; j != S; ++j)
            std::tie(c, t[j - 1]) = addmul(t[j], m, mod[j], c);
        tmp = intx::addc(t[S], c);
        t[S - 1] = tmp.value;
        t[S] = d + tmp.carry;  // TODO: Carry is 0 for sparse modulus.
    }

    if (t >= mod)
        t -= mod;

    return static_cast<UintT>(t);
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

/// The building blocks of modinv_scaled(): the safegcd algorithm of Bernstein and Yang,
/// "Fast constant-time gcd computation and modular inversion", https://eprint.iacr.org/2019/266,
/// in the variable-time form of libsecp256k1's modinv64_var,
/// https://github.com/bitcoin-core/secp256k1/blob/master/doc/safegcd_implementation.md.
/// The values are signed integers of N+1 64-bit words in two's complement, N the words of UintT.
namespace safegcd
{
/// The number of divsteps in a batch.
/// The matrix entries then fit in int64 and the limb sums of update_de() in 127 bits.
inline constexpr int BATCH = 61;

/// The transition matrix of BATCH divsteps: 2ᴮᴬᵀᶜᴴ⋅[f', g'] = [u v; q r]⋅[f, g].
struct Matrix
{
    int64_t u;
    int64_t v;
    int64_t q;
    int64_t r;
};

/// Computes a⋅b as a two's complement 128-bit value.
constexpr intx::uint128 mul_su(int64_t a, uint64_t b) noexcept
{
    auto p = intx::umul(static_cast<uint64_t>(a), b);
    p[1] -= b & static_cast<uint64_t>(a >> 63);
    return p;
}

/// Computes a⋅b as a two's complement 128-bit value.
constexpr intx::uint128 mul_ss(int64_t a, int64_t b) noexcept
{
    auto p = intx::umul(static_cast<uint64_t>(a), static_cast<uint64_t>(b));
    p[1] -= (static_cast<uint64_t>(b) & static_cast<uint64_t>(a >> 63)) +
            (static_cast<uint64_t>(a) & static_cast<uint64_t>(b >> 63));
    return p;
}

/// Shifts the two's complement 128-bit x right by 64 bits, keeping the sign.
constexpr intx::uint128 sar64(const intx::uint128& x) noexcept
{
    return {x[1], static_cast<uint64_t>(static_cast<int64_t>(x[1]) >> 63)};
}

/// Applies BATCH divsteps to f and g given by their low words, f odd.
/// Returns the new eta = -delta and the transition matrix in t.
constexpr int64_t divsteps(int64_t eta, uint64_t f, uint64_t g, Matrix& t) noexcept
{
    // Each iteration does the divsteps for the trailing zeros of g at once, then swaps f and g
    // if delta > 0 and cancels up to 5 low bits of g by adding a multiple of f, but no more bits
    // than the divsteps until the next swap. The matrix is kept modulo 2⁶⁴.
    uint64_t u = 1;
    uint64_t v = 0;
    uint64_t q = 0;
    uint64_t r = 1;
    int i = BATCH;  // The remaining divsteps.
    while (true)
    {
        const auto zeros = std::countr_zero(g | (~uint64_t{0} << i));
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;
        if (i == 0)
            break;

        uint64_t neg_g = 0;
        if (eta < 0)
        {
            eta = -eta;
            neg_g = f;
            f = g;
            g = -neg_g;
            const auto u0 = u;
            u = q;
            q = -u0;
            const auto v0 = v;
            v = r;
            r = -v0;
        }
        else
            neg_g = -g;
        const auto limit = std::min(static_cast<int>(eta) + 1, i);
        // f⁻¹ ≡ (3⋅f) ⊕ 2 (mod 2⁵): a single multiplication on the critical path.
        const auto w = (neg_g * ((3 * f) ^ 2)) & ((~uint64_t{0} >> (64 - limit)) & 31);
        g += f * w;
        q += u * w;
        r += v * w;
    }
    t = {static_cast<int64_t>(u), static_cast<int64_t>(v), static_cast<int64_t>(q),
        static_cast<int64_t>(r)};
    return eta;
}

/// Computes [f, g] = t⋅[f, g] / 2ᴮᴬᵀᶜᴴ on the low len words, the division is exact.
/// Requires the words from len on to be the sign extension.
template <typename SignedT>
constexpr void update_fg(size_t len, SignedT& f, SignedT& g, const Matrix& t) noexcept
{
    constexpr auto S = BATCH;
    const auto [u, v, q, r] = t;
    intx::uint128 cf;
    intx::uint128 cg;
    uint64_t pf = 0;  // The low word of the previous partial sum.
    uint64_t pg = 0;
    for (size_t i = 0; i < len - 1; ++i)
    {
        cf += mul_su(u, f[i]) + mul_su(v, g[i]);
        cg += mul_su(q, f[i]) + mul_su(r, g[i]);
        if (i != 0)
        {
            f[i - 1] = (pf >> S) | (cf[0] << (64 - S));
            g[i - 1] = (pg >> S) | (cg[0] << (64 - S));
        }
        pf = cf[0];
        pg = cg[0];
        cf = sar64(cf);
        cg = sar64(cg);
    }
    const auto ft = static_cast<int64_t>(f[len - 1]);
    const auto gt = static_cast<int64_t>(g[len - 1]);
    cf += mul_ss(u, ft) + mul_ss(v, gt);
    cg += mul_ss(q, ft) + mul_ss(r, gt);
    if (len != 1)
    {
        f[len - 2] = (pf >> S) | (cf[0] << (64 - S));
        g[len - 2] = (pg >> S) | (cg[0] << (64 - S));
    }
    f[len - 1] = (cf[0] >> S) | (cf[1] << (64 - S));
    g[len - 1] = (cg[0] >> S) | (cg[1] << (64 - S));
}

/// Computes [d, e] = (t⋅[d, e] + mod⋅[md, me]) / 2ᴮᴬᵀᶜᴴ, with md and me making the division
/// exact. Requires d and e in (-2⋅mod, mod) and mod_inv⋅mod ≡ 1 (mod 2⁶⁴).
/// The results are in (-2⋅mod, mod).
template <typename SignedT, typename UintT>
constexpr void update_de(
    SignedT& d, SignedT& e, const Matrix& t, const UintT& mod, uint64_t mod_inv) noexcept
{
    constexpr auto S = BATCH;
    constexpr auto TOP = UintT::num_words;
    constexpr uint64_t MASK = (uint64_t{1} << S) - 1;
    const auto [u, v, q, r] = t;
    // Start with md and me adding mod for each negative d or e: this keeps the range.
    const auto sd = static_cast<int64_t>(d[TOP]) >> 63;
    const auto se = static_cast<int64_t>(e[TOP]) >> 63;
    auto md = (u & sd) + (v & se);
    auto me = (q & sd) + (r & se);
    auto cd = mul_su(u, d[0]) + mul_su(v, e[0]);
    auto ce = mul_su(q, d[0]) + mul_su(r, e[0]);
    md -= static_cast<int64_t>((mod_inv * cd[0] + static_cast<uint64_t>(md)) & MASK);
    me -= static_cast<int64_t>((mod_inv * ce[0] + static_cast<uint64_t>(me)) & MASK);
    cd += mul_su(md, mod[0]);
    ce += mul_su(me, mod[0]);
    auto pd = cd[0];  // The low word of the previous partial sum.
    auto pe = ce[0];
    cd = sar64(cd);
    ce = sar64(ce);
    for (size_t i = 1; i < TOP; ++i)
    {
        cd += mul_su(u, d[i]) + mul_su(v, e[i]) + mul_su(md, mod[i]);
        ce += mul_su(q, d[i]) + mul_su(r, e[i]) + mul_su(me, mod[i]);
        d[i - 1] = (pd >> S) | (cd[0] << (64 - S));
        e[i - 1] = (pe >> S) | (ce[0] << (64 - S));
        pd = cd[0];
        pe = ce[0];
        cd = sar64(cd);
        ce = sar64(ce);
    }
    // The top words are in [-2, 0], so the products fit in int64.
    const auto dt = static_cast<int64_t>(d[TOP]);
    const auto et = static_cast<int64_t>(e[TOP]);
    cd += sar64({0, static_cast<uint64_t>(u * dt + v * et)});
    ce += sar64({0, static_cast<uint64_t>(q * dt + r * et)});
    d[TOP - 1] = (pd >> S) | (cd[0] << (64 - S));
    e[TOP - 1] = (pe >> S) | (ce[0] << (64 - S));
    d[TOP] = (cd[0] >> S) | (cd[1] << (64 - S));
    e[TOP] = (ce[0] >> S) | (ce[1] << (64 - S));
}
}  // namespace safegcd

/// Computes scale⋅x⁻¹ % mod, i.e. the modular inverse of x scaled by the given factor.
/// Returns 0 for non-invertible x (including x == 0).
/// Requires an odd mod not less than 3, and both x and scale less than mod.
/// Runs in variable time.
template <typename UintT>
constexpr UintT modinv_scaled(const UintT& x, const UintT& scale, const UintT& mod) noexcept
{
    assert((mod & 1) == 1);
    assert(mod >= 3);
    assert(x < mod);
    assert(scale < mod);  // Otherwise e starts out of its range.

    using namespace safegcd;
    constexpr auto W = UintT::num_words + 1;
    using SignedT = intx::uint<64 * W>;

    // Keeps d⋅x ≡ scale⋅f and e⋅x ≡ scale⋅g (mod mod) while the divsteps drive g to 0.
    // The scale is the initial e and the algorithm is linear in it,
    // so any factor can be folded into the result for free.
    const auto mod_inv = modinv_pow2(mod[0]);
    SignedT d = 0;
    SignedT e = scale;
    SignedT f = mod;
    SignedT g = x;
    int64_t eta = -1;  // eta = -delta, delta starts at 1.
    size_t len = W;    // The active words of f and g, the rest is the sign extension.
    while (true)
    {
        Matrix t;
        eta = divsteps(eta, f[0], g[0], t);
        update_fg(len, f, g, t);
        update_de(d, e, t, mod, mod_inv);

        uint64_t g_any = 0;
        for (size_t i = 0; i < len; ++i)
            g_any |= g[i];
        if (g_any == 0)
            break;

        if (len >= 2)
        {
            const auto fs = static_cast<uint64_t>(static_cast<int64_t>(f[len - 2]) >> 63);
            const auto gs = static_cast<uint64_t>(static_cast<int64_t>(g[len - 2]) >> 63);
            if (((f[len - 1] ^ fs) | (g[len - 1] ^ gs)) == 0)
                --len;
        }
    }

    // Now f = ±gcd(x, mod), and d = ±scale⋅x⁻¹ if the gcd is 1.
    const auto f_sign = static_cast<uint64_t>(static_cast<int64_t>(f[len - 1]) >> 63);
    if (f[0] != (f_sign | 1))
        return 0;
    for (size_t i = 1; i < len; ++i)
    {
        if (f[i] != f_sign)
            return 0;
    }

    // Move d from (-2⋅mod, mod) to [0, mod), negated if f = -1.
    const SignedT m = mod;
    if (static_cast<int64_t>(d[W - 1]) < 0)
        d += m;
    if (f_sign != 0)
        d = -d;
    if (static_cast<int64_t>(d[W - 1]) < 0)
        d += m;
    return static_cast<UintT>(d);
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
#ifdef __x86_64__
    // The kernel selection below must fold to a single call.
    [[gnu::always_inline]]
#endif
    constexpr UintT mul(const UintT& x, const UintT& y) const noexcept
    {
#ifdef __x86_64__
        if constexpr (std::is_same_v<UintT, intx::uint256>)
        {
            if (!std::is_constant_evaluated())
            {
                if ((mod_[1] & mod_[2] & mod_[3]) == ~uint64_t{0})
                    return mul_mont_256_pm(x, y, mod_, mod_inv_);
                if (mod_ == P256_FIELD_PRIME)
                    return mul_mont_256_p256(x, y, mod_, mod_inv_);
                if (mod_[3] < (uint64_t{1} << 63))
                    return mul_mont_256_sparse(x, y, mod_, mod_inv_);
                return mul_mont_256(x, y, mod_, mod_inv_);
            }
        }
#endif

        return mul_mont_generic(x, y, mod_, mod_inv_);
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
