// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "mulmod.hpp"

namespace evmone::crypto
{
namespace
{
/// The almost Montgomery multiplication for 4 words.
void mul_amm_256(std::span<uint64_t, 4> r, std::span<const uint64_t, 4> x,
    std::span<const uint64_t, 4> y, std::span<const uint64_t, 4> mod, uint64_t mod_inv) noexcept
{
    static constexpr size_t N = 4;

    assert(mod[0] * mod_inv + 1 == 0);  // The negative modulus inverse identity.

    // Local accumulator t[] avoids aliasing penalties when r overlaps x or y.
    std::array<uint64_t, N> t;  // NOLINT(*-pro-type-member-init)
    const auto t_lo = std::span{t}.subspan<0, N - 1>();
    const auto t_hi = std::span{t}.subspan<1>();
    const auto mod_hi = mod.subspan<1>();

    // First iteration: t is uninitialized, so use mul instead of addmul.
    bool t_carry = false;
    {
        const auto c1 = mul(t, x, y[0]);

        const auto m = t[0] * mod_inv;
        const auto p = umul(mod[0], m) + t[0];
        assert(p[0] == 0);  // The lowest word is canceled by m.

        const auto c3 = addmul(t_lo, t_hi, mod_hi, m, p[1]);
        std::tie(t[N - 1], t_carry) = addc(c1, c3);
    }

    // Remaining 3 iterations.
#pragma GCC unroll N - 1
    for (size_t i = 1; i != N; ++i)
    {
        const auto c1 = addmul(t, t, x, y[i]);

        const auto m = t[0] * mod_inv;
        const auto p = umul(mod[0], m) + t[0];
        assert(p[0] == 0);  // The lowest word is canceled by m.

        const auto c3 = addmul(t_lo, t_hi, mod_hi, m, p[1]);
        std::tie(t[N - 1], t_carry) = addc(c1, c3, t_carry);
    }

    assert(!t_carry || less(t, mod));  // t_carry => t < mod.
    if (t_carry)
        sub(t, mod);

    std::ranges::copy(t, r.begin());
}
}  // namespace

EVMONE_PRESERVE_NONE void sqr_n_amm_256_generic(
    uint64_t* r, const uint64_t* x, size_t k, const uint64_t* mod, uint64_t mod_inv) noexcept
{
    const std::span<uint64_t, 4> rs{r, 4};
    if (r != x)
        std::copy_n(x, 4, r);
    for (; k != 0; --k)
        mul_amm_256(rs, rs, rs, std::span<const uint64_t, 4>{mod, 4}, mod_inv);
}

EVMONE_PRESERVE_NONE void mul_amm_generic(uint64_t* r_ptr, const uint64_t* x_ptr,
    const uint64_t* y_ptr, const uint64_t* mod_ptr, uint64_t mod_inv, size_t n) noexcept
{
    if (n == 4)
    {
        mul_amm_256(std::span<uint64_t, 4>{r_ptr, 4}, std::span<const uint64_t, 4>{x_ptr, 4},
            std::span<const uint64_t, 4>{y_ptr, 4}, std::span<const uint64_t, 4>{mod_ptr, 4},
            mod_inv);
        return;
    }
    const std::span r{r_ptr, n};
    const std::span x{x_ptr, n};
    const std::span y{y_ptr, n};
    const std::span mod{mod_ptr, n};

    // Use Coarsely Integrated Operand Scanning (CIOS) method with the "almost" reduction.
    // GCC 11-13 generate several times slower loops without this fact.
    INTX_REQUIRE(n > 0);
    INTX_REQUIRE(mod.back() != 0);
    INTX_REQUIRE(mod[0] * mod_inv + 1 == 0);                     // Negative mod inverse identity.
    INTX_REQUIRE(r.data() != x.data() && r.data() != y.data());  // r must not alias inputs.

    const auto r_lo = r.subspan(0, n - 1);
    const auto r_hi = r.subspan(1);
    const auto mod_hi = mod.subspan(1);

    // First iteration: r is uninitialized, so use mul instead of addmul.
    bool r_carry = false;
    {
        const auto c1 = crypto::mul(r, x, y[0]);

        const auto m = r[0] * mod_inv;
        const auto p = umul(mod[0], m) + r[0];
        assert(p[0] == 0);  // The lowest word is canceled by m.

        const auto c3 = addmul(r_lo, r_hi, mod_hi, m, p[1]);
        std::tie(r[n - 1], r_carry) = intx::addc(c1, c3);
    }

    // Remaining iterations.
    for (size_t i = 1; i != n; ++i)
    {
        const auto c1 = addmul(r, r, x, y[i]);

        const auto m = r[0] * mod_inv;
        const auto p = umul(mod[0], m) + r[0];
        assert(p[0] == 0);  // The lowest word is canceled by m.

        const auto c3 = addmul(r_lo, r_hi, mod_hi, m, p[1]);
        std::tie(r[n - 1], r_carry) = intx::addc(c1, c3, r_carry);
    }

    assert(!r_carry || less(r, mod));  // r_carry => r < mod.
    if (r_carry)
        sub(r, mod);
}

}  // namespace evmone::crypto
