// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>
#include <memory>
#include <string_view>

// TODO(intx): Add ""_u384.
inline constexpr auto operator""_u384(const char* s)
{
    return intx::from_string<intx::uint384>(s);
}

namespace evmmax
{
using bytes_view = std::basic_string_view<uint8_t>;

class ModState
{
public:
    using uint = intx::uint384;

    uint mod;
    uint r_squared;
    uint64_t mod_inv;
    size_t num_elems = 0;
    std::unique_ptr<uint[]> elems;

    uint to_mont(const uint& x) noexcept;
    uint from_mont(const uint& x) noexcept;

    uint mul(const uint& x, const uint& y) noexcept;

    uint add(const uint& x, const uint& y) const noexcept;

};

std::unique_ptr<ModState> setup(bytes_view modulus, size_t vals_used);
}  // namespace evmmax
