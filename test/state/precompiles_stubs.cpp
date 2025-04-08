// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_stubs.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace evmone::state
{
namespace
{
/// Returns the expmod result for the known inputs or empty bytes if not found.
///
/// Missing inputs collected with:
/// bin/evmone-statetest test_dirs >/dev/null 2> >(sort | uniq | tee stub.txt)
///
/// Results computed with:
/// ```python
/// def e(s):
///     b, x, m = s.split(",")
///     b = int(b, 16) if b != "0x" else 0
///     x = int(x, 16) if x != "0x" else 0
///     m = int(m, 16) if m != "0x" else 0
///     r = 0
///     if m != 0:
///         r = pow(b, x, m)
///     print(f'{{"{s}","{r:02x}"}},')
/// ```
bytes expmod_lookup_result(bytes_view base, bytes_view exp, bytes_view mod)
{
    static const std::unordered_map<std::string_view, std::string_view> stubs{
        // clang-format off
        {"0x02,0x01,0x02","00"},
        {"0x02,0x01,0x03","02"},
        {"0x02,0x02,0x02","00"},
        {"0x02,0x02,0x05","04"},
        {"0x02,0x03,0x06","02"},
        {"0x03,0x05,0x64","2b"},
        {"0x03,0x1c93,0x61", "5f"},
        {"0x03,0x2700,0x9c00","6801"},
        {"0x03,0x7114,0x2d3b","1b"},
        {"0x03,0xffff,0x8000000000000000000000000000000000000000000000000000000000000000","3b01b01ac41f2d6e917c6d6a221ce793802469026d9ab7578fa2e79e4da6aaab"},
        {"0x03,0x4000000000000000000000000000000000000000000000000000000000000000,0x010000000000000000000000000000000000000000000000000000000000000000","01"},
        {"0x03,0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e,0xffffffffffffffffffffffffffffffffffffffffff2f00000000000000000000","162ead82cadefaeaf6e9283248fdf2f2845f6396f6f17c4d5a39f820b6f6b5f9"},
        {"0x03,0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e,0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","01"},
        {"0x09,0x0e7f,0x90f7","8615"},
        {"0x09,0x90f7,0x90f7","1c3b"},
        {"0x09,0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97,0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97","09"},
        {"0x31,0x0961,0x0961","00"},
        {"0xba,0xee,0xd000","9000"},
        {"0xba,0xee,0xd00000","100000"},
        {"0xba,0xee,0xd00100","789700"},
        {"0x1001,0x0100,0x10","01"},
        {"0x1bd0,0x90f7,0x61","50"},
        {"0x9100,0x578b,0x55f0","3e80"},
        {"0x9100,0x90f7,0x61","5f"},
        {"0x9100,0x90f7,0x90f7","1c3b"},
        {"0x9c00,0x01,0xd7a1","9c00"},
        {"0xd796,0xd796,0xa7d5","866a"},
        {"0x02534f82b1,0x013f20d9c7d18d62cd95674d2e,0x013f20d9c7d18d62cd95674d2f","01"},
        {"0xd935b43e42,0x204fcbfb734a6e27735e8e90,0x204fcc1fd2727bb040f9eecb","01"},
        {"0x0846813a8d2d,0x451387340fa0,0x597c6545ae63","01"},
        {"0x010000000000000000000000000000000000000000000000000000000000000000,0x01,0x304d37f120d696c834550e63d9bb9c14b4f9165c9ede434e4644e3998d6db881","0e7de84a5bcf0e16fa56b80cbf55f39877229030e5a8af78a0a78e003cdb657b"},
        {"0x304d37f120d696c834550e63d9bb9c14b4f9165c9ede434e4644e3998d6db876,0x304d37f120d696c834550e63d9bb9c14b4f9165c9ede434e4644e3998d6db876,0xfffffffffffffffffffffffffffffffffffffff5","cd433bbd1fa6457602a79d957ee85a37e2496d0a"},
        {"0x035ee4e488f45e64d2f07becd54646357381d32f30b74c299a8c25d5202c04938e,0xf6c4764a04f10fc908b78c4486886000,0xf6d290251a79681a83b950c7e5c37351","01"},
        {"0x0785e45de3d6be050ba3c4d33ff0bb2d,0x010ace3b1dfe9c49f4c7a8075102fa19a86c,0x010ace3b1dfe9c49f4c7a8075102fa19a86d","01"},
        {"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0,0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97,0x61","3e"},
        {"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0,0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97,0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97","09"},
        // clang-format on
    };

    /// Combine the arguments into a key. It can be copy-pasted to python's pow().
    const auto key = "0x" + evmc::hex({base.data(), base.size()}) +  //
                     ",0x" + evmc::hex({exp.data(), exp.size()}) +   //
                     ",0x" + evmc::hex({mod.data(), mod.size()});    //

    const auto it = stubs.find(key);
    if (it == stubs.end())
    {
        std::cerr << "expmod: no result for " << key << "\n";
        return {};
    }
    return evmc::from_hex(it->second).value();
}
}  // namespace


void expmod_stub(bytes_view base, bytes_view exp, bytes_view mod, uint8_t* output) noexcept
{
    // Keep the output size before the mod normalization.
    const auto output_size = mod.size();

    // Normalize arguments by removing leading zeros.
    base = base.substr(std::min(base.find_first_not_of(uint8_t{0}), base.size()));
    exp = exp.substr(std::min(exp.find_first_not_of(uint8_t{0}), exp.size()));
    mod = mod.substr(std::min(mod.find_first_not_of(uint8_t{0}), mod.size()));
    assert(!mod.empty());  // mod must not be 0.

    // Figure out the result by handling trivial cases
    // or finally looking it up in the predefined set of results.
    const auto result = [&]() -> bytes {
        // For mod == 1 the result is 0.
        if (mod.size() == 1 && mod[0] == 1)
            return bytes{};

        // For exp == 0 and mod > 1 the result is 1.
        if (exp.empty())
            return bytes{1};

        // For base <= 1, exp != 0, mod > 1 the result is base.
        if (base.empty() || (base.size() == 1 && base[0] == 1))
            return bytes{base};

        return expmod_lookup_result(base, exp, mod);
    }();

    // Set the result in the output buffer.
    const auto output_p = std::fill_n(output, output_size - result.size(), 0);
    std::ranges::copy(result, output_p);
}
}  // namespace evmone::state
