// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <iostream>

using namespace intx;

namespace evmmax::utils
{

template <typename UIntT>
UIntT ee_inverse(const UIntT& y, const UIntT& m)
{
    UIntT old_r = y;
    UIntT r = m;

    UIntT old_s = 1;
    UIntT s = 0;

    UIntT old_t = 0;
    UIntT t = 1;

    while (r != 0)
    {
        const auto q = old_r / r;
        UIntT tmp;

        tmp = old_r;
        old_r = r;
        r = tmp - q * r;

        tmp = old_s;
        old_s = s;
        s = tmp - q * s;

        tmp = old_t;
        old_t = t;
        t = tmp - q * t;
    }

    if (old_s >= m)
        old_s += m;

    return old_s;
}

template <typename UIntT>
void swap(UIntT& a, UIntT& b)
{
    const auto t = a;
    a = b;
    b = t;
}

template <typename UIntT>
UIntT bee_inverse(const UIntT& y, const UIntT& m, const UIntT& multiplier = 1)
{
    // `m` must be odd
    assert(m && 1 == 1);

    if (y == 0)
        return 0;

    auto a = y;           // r0
    auto b = m;           // r1
    auto u = multiplier;  // s0
    auto v = UIntT{0};    // s1

    while (a != 0)
    {
        if ((a & 1) == 0)
        {
            a >>= 1;

            if ((u & 1) == 1)
                u += m;  // TODO: Check overflow
            u >>= 1;
        }
        else
        {
            if (a < b)
            {
                swap(a, b);
                swap(u, v);
            }

            a = (a - b);
            u = u >= v ? (u - v) : (u + m - v);
        }
    }

    if (b == 1)
        return v;
    else
        return 0;
}

template<typename UIntT>
inline ecc::ProjPoint<UIntT> shamir_multipy(const ModArith<UIntT>& m, const UIntT& b3, const UIntT& u,
    const ecc::ProjPoint<UIntT>& g, const UIntT& v, const ecc::ProjPoint<UIntT>& q)
{
    ecc::ProjPoint<UIntT> r;
    const auto h = ecc::add(m, g, q, b3);

    const auto u_lz = clz(u);
    const auto v_lz = clz(v);

    auto lz = std::min(u_lz, v_lz);

    if (lz == UIntT::num_bits)
        return {};

    if (u_lz < v_lz)
        r = g;
    else if (u_lz > v_lz)
        r = q;
    else
        r = h;

    auto mask = (UIntT{1} << (UIntT::num_bits - 1 - lz - 1));

    while (mask != 0)
    {
        r = ecc::dbl(m, r, b3);
        if (u & v & mask)
            r = ecc::add(m, r, h, b3);
        else if (u & mask)
            r = ecc::add(m, r, g, b3);
        else if (v & mask)
            r = ecc::add(m, r, q, b3);

        mask >>= 1;
    }

    return r;
}

}  // namespace evmmax::utils
