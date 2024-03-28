// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>

namespace evmmax
{

namespace
{
inline constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    using namespace intx;
    const auto p = umul(a, b) + t + c;
    return {p[1], p[0]};
}
}  // namespace

/// The modular arithmetic operations for EVMMAX (EVM Modular Arithmetic Extensions).
template <typename UintT>
class ModArith
{
public:
    const UintT mod;  ///< The modulus.

private:
    const UintT m_r_squared;  ///< R² % mod.

    /// The modulus inversion, i.e. the number N' such that mod⋅N' = 2⁶⁴-1.
    const uint64_t m_mod_inv;

public:
    explicit ModArith(const UintT& modulus) noexcept;

    constexpr explicit ModArith(
        const UintT& modulus, const UintT& r_squared, uint64_t modulus_inv) noexcept
      : mod{modulus}, m_r_squared{r_squared}, m_mod_inv{modulus_inv}
    {
        // TODO: Add r_squared and modulus_inv values verification
    }

    /// Converts a value to Montgomery form.
    ///
    /// This is done by using Montgomery multiplication mul(x, R²)
    /// what gives aR²R⁻¹ % mod = aR % mod.
    constexpr UintT to_mont(const UintT& x) const noexcept { return mul(x, m_r_squared); }

    /// Converts a value in Montgomery form back to normal value.
    ///
    /// Given the x is the Montgomery form x = aR, the conversion is done by using
    /// Montgomery multiplication mul(x, 1) what gives aRR⁻¹ % mod = a % mod.
    UintT from_mont(const UintT& x) const noexcept;

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

        using namespace intx;
        constexpr auto S = UintT::num_words;

        intx::uint<UintT::num_bits + 64> t;
        for (size_t i = 0; i != S; ++i)
        {
            uint64_t c = 0;
            for (size_t j = 0; j != S; ++j)
                std::tie(c, t[j]) = addmul(t[j], x[j], y[i], c);
            auto tmp = addc(t[S], c);
            t[S] = tmp.value;
            auto d = tmp.carry;

            c = 0;
            auto m = t[0] * m_mod_inv;
            std::tie(c, t[0]) = addmul(t[0], m, mod[0], c);
            for (size_t j = 1; j != S; ++j)
                std::tie(c, t[j - 1]) = addmul(t[j], m, mod[j], c);
            tmp = addc(t[S], c);
            t[S - 1] = tmp.value;
            t[S] = d + tmp.carry;  // TODO: Carry is 0 for sparse modulus.
        }

        if (t >= mod)  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
            t -= mod;

        // TODO: use `explicit operator uint<M>() const noexcept` when it will be constexpr.
        intx::uint<UintT::num_bits> r;
        for (size_t i = 0; i < intx::uint<UintT::num_bits>::num_words; ++i)
            r[i] = t[i];

        return r;
    }

    /// Performs a modular addition. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    UintT add(const UintT& x, const UintT& y) const noexcept;

    /// Performs a modular subtraction. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    UintT sub(const UintT& x, const UintT& y) const noexcept;
};
}  // namespace evmmax
