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
}  // namespace evmmax
