// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evmmax.hpp"

using namespace intx;

namespace evmmax
{
namespace
{
constexpr auto BLS12384Mod =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab_u384;

inline constexpr uint64_t mul_inv64(uint64_t base) noexcept
{
    uint64_t result = 1;
    for (auto _ = 0; _ < 64; ++_)
    {
        result *= base;
        base *= base;
    }
    return result;
}

inline constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    const auto p = umul(a, b) + t + c;
    return {p[1], p[0]};
}

}  // namespace

std::unique_ptr<ModState> setup(bytes_view modulus, size_t vals_used)
{
    if (vals_used > 256)
        throw std::invalid_argument{"too much elements"};

    if (modulus.size() != sizeof(uint384))
        throw std::invalid_argument{"incorrect modulus length, expected 384 bits"};

    const auto mod_arg = be::unsafe::load<uint384>(modulus.data());
    if (mod_arg != BLS12384Mod)
        throw std::invalid_argument{"only BLS12-384 supported"};

    const auto r_squared = intx::uint<384 * 2 + 64>{1} << 384 * 2;
    const auto r_squared_mod = intx::udivrem(r_squared, mod_arg).rem;

    auto state = std::make_unique<ModState>();
    state->mod = mod_arg;
    state->r_squared = r_squared_mod;
    state->mod_inv = mul_inv64(-mod_arg[0]);
    state->num_elems = vals_used;
    state->elems = std::unique_ptr<uint384[]>(new uint384[vals_used]);
    return state;
}

ModState::uint ModState::mul(const ModState::uint& a, const ModState::uint& b) noexcept
{
    static constexpr auto S = ModState::uint::num_words;

    uint64_t t[S + 2]{};
    for (size_t i = 0; i != S; ++i)
    {
        uint64_t c = 0;
        for (size_t j = 0; j != S; ++j)
        {
            std::tie(c, t[j]) = addmul(t[j], a[j], b[i], c);
        }
        auto tmp = addc(t[S], c);
        t[S] = tmp.value;
        t[S + 1] = tmp.carry;

        c = 0;
        auto m = t[0] * mod_inv;
        for (size_t j = 0; j != S; ++j)
        {
            std::tie(c, t[j]) = addmul(t[j], m, mod[j], c);
        }
        tmp = addc(t[S], c);
        t[S] = tmp.value;
        t[S + 1] += tmp.carry;

        for (size_t j = 0; j != S + 1; ++j)
        {
            t[j] = t[j + 1];
        }
    }

    intx::uint<(S + 1) * 64> tt;
    for (size_t j = 0; j != S + 1; ++j)
        tt[j] = t[j];

    if (tt >= mod)
        tt -= mod;

    return static_cast<ModState::uint>(tt);
}

ModState::uint ModState::to_mont(const ModState::uint& x) noexcept
{
    return mul(x, r_squared);
}

ModState::uint ModState::from_mont(const ModState::uint& x) noexcept
{
    return mul(x, 1);
}

ModState::uint ModState::add(const ModState::uint& x, const ModState::uint& y) const noexcept
{
    const auto s = addc(x, y);  // FIXME: can overflow only if prime is max size (e.g. 255 bits).
    const auto d = subc(s.value, mod);
    return (!s.carry && d.carry) ? s.value : d.value;
}

ModState::uint ModState::sub(const ModState::uint& x, const ModState::uint& y) const noexcept
{
    const auto d = subc(x, y);
    const auto s = d.value + mod;
    return (d.carry) ? s : d.value;
}
}  // namespace evmmax
