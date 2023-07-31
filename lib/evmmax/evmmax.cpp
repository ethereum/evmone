// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmmax/evmmax.hpp>

using namespace intx;

namespace evmmax
{
namespace
{
/// Compute the modulus inverse for Montgomery multiplication, i.e. N': mod⋅N' = 2⁶⁴-1.
///
/// @param mod0  The least significant word of the modulus.
inline constexpr uint64_t compute_mod_inv(uint64_t mod0) noexcept
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
template <typename UintT>
inline UintT compute_r_squared(const UintT& mod) noexcept
{
    // R is 2^num_bits, R² is 2^(2*num_bits) and needs 2*num_bits+1 bits to represent,
    // rounded to 2*num_bits+64) for intx requirements.
    static constexpr auto r2 = intx::uint<UintT::num_bits * 2 + 64>{1} << (UintT::num_bits * 2);
    return intx::udivrem(r2, mod).rem;
}

inline constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    const auto p = umul(a, b) + t + c;
    return {p[1], p[0]};
}
}  // namespace

template <typename UintT>
ModArith<UintT>::ModArith(const UintT& modulus) noexcept
  : mod{modulus}, m_r_squared{compute_r_squared(modulus)}, m_mod_inv{compute_mod_inv(modulus[0])}
{}

template <typename UintT>
UintT ModArith<UintT>::mul(const UintT& x, const UintT& y) const noexcept
{
    // Coarsely Integrated Operand Scanning (CIOS) Method
    // Based on 2.3.2 from
    // High-Speed Algorithms & Architectures For Number-Theoretic Cryptosystems
    // https://www.microsoft.com/en-us/research/wp-content/uploads/1998/06/97Acar.pdf

    static constexpr auto S = UintT::num_words;

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

    return static_cast<UintT>(t);
}

template <typename UintT>
UintT ModArith<UintT>::to_mont(const UintT& x) const noexcept
{
    return mul(x, m_r_squared);
}

template <typename UintT>
UintT ModArith<UintT>::from_mont(const UintT& x) const noexcept
{
    return mul(x, 1);
}

template <typename UintT>
UintT ModArith<UintT>::add(const UintT& x, const UintT& y) const noexcept
{
    const auto s = addc(x, y);  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
    const auto d = subc(s.value, mod);
    return (!s.carry && d.carry) ? s.value : d.value;
}

template <typename UintT>
UintT ModArith<UintT>::sub(const UintT& x, const UintT& y) const noexcept
{
    const auto d = subc(x, y);
    const auto s = d.value + mod;
    return (d.carry) ? s : d.value;
}

template class ModArith<uint256>;
template class ModArith<uint384>;
}  // namespace evmmax
