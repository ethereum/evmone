// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>

namespace evmmax
{

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

    /// Compute the modulus inverse for Montgomery multiplication, i.e. N': mod⋅N' = 2⁶⁴-1.
    ///
    /// @param mod0  The least significant word of the modulus.
    static constexpr uint64_t compute_mod_inv(uint64_t mod0) noexcept
    {
        // TODO: Find what is this algorithm and why it works.
        uint64_t base = 0 - mod0;
        uint64_t result = 1;
        for (auto i = 0; i < 64; ++i)
        {
            result *= base;
            base *= base;
        }
        return result;
    }

    /// Compute R² % mod.
    static constexpr UintT compute_r_squared(const UintT& mod) noexcept
    {
        // R is 2^num_bits, R² is 2^(2*num_bits) and needs 2*num_bits+1 bits to represent,
        // rounded to 2*num_bits+64) for intx requirements.
        constexpr auto r2 = intx::uint<UintT::num_bits * 2 + 64>{1} << (UintT::num_bits * 2);
        return intx::udivrem(r2, mod).rem;
    }

    static constexpr std::pair<uint64_t, uint64_t> addmul(
        uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
    {
        const auto p = intx::umul(a, b) + t + c;
        return {p[1], p[0]};
    }

public:
    constexpr explicit ModArith(const UintT& modulus) noexcept
      : mod{modulus},
        m_r_squared{compute_r_squared(modulus)},
        m_mod_inv{compute_mod_inv(modulus[0])}
    {}

    /// Converts a value to Montgomery form.
    ///
    /// This is done by using Montgomery multiplication mul(x, R²)
    /// what gives aR²R⁻¹ % mod = aR % mod.
    constexpr UintT to_mont(const UintT& x) const noexcept { return mul(x, m_r_squared); }

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
            for (size_t j = 0; j != S; ++j)
                std::tie(c, t[j]) = addmul(t[j], x[j], y[i], c);
            auto tmp = intx::addc(t[S], c);
            t[S] = tmp.value;
            const auto d = tmp.carry;  // TODO: Carry is 0 for sparse modulus.

            const auto m = t[0] * m_mod_inv;
            std::tie(c, std::ignore) = addmul(t[0], m, mod[0], 0);
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

    /// Performs a modular addition. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    constexpr UintT add(const UintT& x, const UintT& y) const noexcept
    {
        const auto s = addc(x, y);  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
        const auto d = subc(s.value, mod);
        return (!s.carry && d.carry) ? s.value : d.value;
    }

    /// Performs a modular subtraction. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    constexpr UintT sub(const UintT& x, const UintT& y) const noexcept
    {
        const auto d = subc(x, y);
        const auto s = d.value + mod;
        return (d.carry) ? s : d.value;
    }
};
}  // namespace evmmax
