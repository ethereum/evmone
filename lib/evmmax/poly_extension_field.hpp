// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "evmmax.hpp"
#include "intx/intx.hpp"
#include "span"
#include "vector"

namespace evmmax
{
using uint256 = intx::uint256;
using namespace intx;
using namespace std::literals;


template <typename UintT, typename ModCoeffsT, typename FiledModulusT>
struct PolyExtFieldElem
{
    static constexpr auto degree = ModCoeffsT::DEGREE;
    static constexpr auto arith = ModArith<UintT>(FiledModulusT::MODULUS, FiledModulusT::R_SQUARED);

    std::vector<UintT> coeffs;

    explicit PolyExtFieldElem() { coeffs.resize(degree); }

    explicit PolyExtFieldElem(std::vector<UintT>&& _coeffs) : coeffs(_coeffs)
    {
        assert(coeffs.size() == degree);
    }

    static inline constexpr PolyExtFieldElem add(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y)
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = x.arith.add(x.coeffs[i], y.coeffs[i]);

        return result;
    }

    static inline constexpr PolyExtFieldElem sub(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y)
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.sub(x.coeffs[i], y.coeffs[i]);

        return result;
    }

    static inline constexpr PolyExtFieldElem mul(const PolyExtFieldElem& x, const UintT& c)
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.mul_non_mont(x.coeffs[i], c);

        return result;
    }

    static inline constexpr PolyExtFieldElem mul(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y)
    {
        std::vector<UintT> b(2 * degree - 1);

        // Multiply
        for (size_t i = 0; i < degree; ++i)
        {
            for (size_t j = 0; j < degree; ++j)
                b[i + j] = arith.add(b[i + j], arith.mul_non_mont(x.coeffs[i], y.coeffs[j]));
        }

        // Reduce by irreducible polynomial (extending polynomial)
        while (b.size() > degree)
        {
            auto top = b.back();
            auto exp = b.size() - degree - 1;
            b.pop_back();
            for (size_t i = 0; i < degree; ++i)
                b[i + exp] =
                    arith.sub(b[i + exp], arith.mul_non_mont(top, ModCoeffsT::MODULUS_COEFFS[i]));
        }

        return PolyExtFieldElem(std::move(b));
    }

    static inline constexpr PolyExtFieldElem div(const PolyExtFieldElem& x, UintT c)
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.div(x.coeffs[i], c);

        return result;
    }

    static inline constexpr size_t deg(const std::vector<UintT>& v)
    {
        size_t d = v.size() - 1;

        while (d > 0 && v[d] == 0)
            --d;

        return d;
    }

    static inline constexpr std::vector<UintT> poly_rounded_div(
        const std::vector<UintT>& a, const std::vector<UintT>& b)
    {
        auto dega = deg(a);
        auto degb = deg(b);
        auto temp = a;
        auto o = std::vector<UintT>(a.size());
        if (dega >= degb)
        {
            for (size_t i = dega - degb + 1; i > 0; --i)
            {
                auto d = arith.div(temp[degb + i - 1], b[degb]);
                o[i - 1] = arith.add(o[i - 1], d);
                for (size_t c = 0; c < degb + 1; ++c)
                    temp[c + i - 1] = arith.sub(temp[c + i - 1], o[c]);
            }
        }

        return std::vector<UintT>(
            o.begin(), o.begin() + (typename std::vector<UintT>::difference_type)deg(o) + 1);
    }

    static inline constexpr PolyExtFieldElem inv(const PolyExtFieldElem& x)
    {
        std::vector<UintT> lm(degree + 1);
        lm[0] = 1;
        std::vector<UintT> hm(degree + 1);

        std::vector<UintT> low = x.coeffs;
        low.push_back(0);

        std::vector<UintT> high(degree);
        std::copy(ModCoeffsT::MODULUS_COEFFS, ModCoeffsT::MODULUS_COEFFS + degree, high.begin());
        high.push_back(1);

        while (deg(low) > 0)
        {
            auto r = poly_rounded_div(high, low);
            r.resize(degree + 1);
            auto nm = hm;
            auto _new = high;

            assert(lm.size() == hm.size() && hm.size() == low.size() && low.size() == high.size() &&
                   high.size() == _new.size() && _new.size() == degree + 1);
            for (size_t i = 0; i < degree + 1; ++i)
            {
                for (size_t j = 0; j < degree + 1 - i; ++j)
                {
                    nm[i + j] = arith.sub(nm[i + j], arith.mul_non_mont(lm[i], r[j]));
                    _new[i + j] = arith.sub(_new[i + j], arith.mul_non_mont(low[i], r[j]));
                }
            }

            high = low;
            hm = lm;
            low = _new;
            lm = nm;
        }

        return div(PolyExtFieldElem(std::vector<UintT>(lm.begin(), lm.begin() + degree)), low[0]);
    }

    static inline constexpr PolyExtFieldElem div(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y)
    {
        return mul(x, inv(y));
    }

    static inline constexpr PolyExtFieldElem one()
    {
        std::vector<UintT> _one(degree);
        _one[0] = 1;
        return PolyExtFieldElem<UintT, ModCoeffsT, FiledModulusT>(std::move(_one));
    }

    static inline constexpr PolyExtFieldElem zero()
    {
        std::vector<UintT> _one(degree);
        return PolyExtFieldElem<UintT, ModCoeffsT, FiledModulusT>(std::move(_one));
    }

    template <typename PowUintT>
    static inline constexpr PolyExtFieldElem pow(const PolyExtFieldElem& x, const PowUintT& y)
    {
        if (y == 0)
            return one();
        else if (y == 1)
            return x;
        else if (y % 2 == 0)
            return pow(mul(x, x), y / 2);
        else
            return mul(pow(mul(x, x), y / 2), x);
    }

    static inline constexpr PolyExtFieldElem neg(const PolyExtFieldElem& x)
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.neg(x.coeffs[i]);

        return result;
    }

    static inline constexpr bool eq(const PolyExtFieldElem& x, const PolyExtFieldElem& y)
    {
        for (size_t i = 0; i < degree; ++i)
        {
            if (x.coeffs[i] != y.coeffs[i])
                return false;
        }

        return true;
    }

    friend std::ostream& operator<<(std::ostream& os, const PolyExtFieldElem& x)
    {
        os << "["sv;

        if (!x.coeffs.empty())
        {
            for (size_t i = 0; i < x.coeffs.size() - 1; ++i)
                os << "0x"sv << hex(x.coeffs[i]) << ", ";
            os << "0x"sv << hex(x.coeffs.back());
        }

        os << "]"sv;
        return os;
    }
};

}  // namespace evmmax
