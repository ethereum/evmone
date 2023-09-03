// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>
#include <span>
#include <vector>

namespace evmmax
{
using namespace std::literals;


template <typename ArithT, typename ModCoeffsT>
struct PolyExtFieldElem
{
    using UIntType = ArithT::UIntType;
    static constexpr auto degree = ModCoeffsT::DEGREE;
    static inline const auto arith = ArithT();

    std::vector<UIntType> coeffs;

    explicit PolyExtFieldElem() noexcept { coeffs.resize(degree); }

    explicit PolyExtFieldElem(std::vector<UIntType>&& _coeffs) noexcept : coeffs(_coeffs)
    {
        assert(coeffs.size() == degree);
    }

    ~PolyExtFieldElem() noexcept = default;
    PolyExtFieldElem(const PolyExtFieldElem&) noexcept = default;

    static inline constexpr PolyExtFieldElem add(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y) noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = x.arith.add(x.coeffs[i], y.coeffs[i]);

        return result;
    }

    static inline constexpr PolyExtFieldElem sub(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y) noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.sub(x.coeffs[i], y.coeffs[i]);

        return result;
    }

    static inline constexpr PolyExtFieldElem mul(
        const PolyExtFieldElem& x, const UIntType& c) noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.mul(x.coeffs[i], c);

        return result;
    }

    static inline PolyExtFieldElem mul(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y) noexcept
    {
        std::vector<UIntType> b(2 * degree - 1);

        // Multiply
        for (size_t i = 0; i < degree; ++i)
        {
            for (size_t j = 0; j < degree; ++j)
                b[i + j] = arith.add(b[i + j], arith.mul(x.coeffs[i], y.coeffs[j]));
        }

        // Reduce by irreducible polynomial (extending polynomial)
        while (b.size() > degree)
        {
            auto top = b.back();
            auto exp = b.size() - degree - 1;
            b.pop_back();
            for (const auto& mc : ModCoeffsT::MODULUS_COEFFS)
                b[mc.first + exp] = arith.sub(b[mc.first + exp], arith.mul(top, mc.second));
        }

        return PolyExtFieldElem(std::move(b));
    }

    static inline constexpr PolyExtFieldElem div(const PolyExtFieldElem& x, UIntType c) noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.div(x.coeffs[i], c);

        return result;
    }

    static inline constexpr size_t deg(const std::vector<UIntType>& v) noexcept
    {
        size_t d = v.size() - 1;

        while (d > 0 && v[d] == 0)
            --d;

        return d;
    }

    static inline std::vector<typename ArithT::UIntType> poly_rounded_div(
        const std::vector<UIntType>& a, const std::vector<UIntType>& b) noexcept
    {
        auto dega = deg(a);
        auto degb = deg(b);
        auto temp = a;
        auto o = std::vector<typename ArithT::UIntType>(a.size());
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

        return std::vector<UIntType>(
            o.begin(), o.begin() + (typename std::vector<UIntType>::difference_type)deg(o) + 1);
    }

    static inline PolyExtFieldElem inv(const PolyExtFieldElem& x) noexcept
    {
        std::vector<UIntType> lm(degree + 1);
        lm[0] = arith.one_mont();
        std::vector<UIntType> hm(degree + 1);

        std::vector<UIntType> low = x.coeffs;
        low.push_back(0);

        std::vector<UIntType> high(degree);
        for (const auto& mc : ModCoeffsT::MODULUS_COEFFS)
            high[mc.first] = mc.second;
        high.push_back(arith.one_mont());

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
                    nm[i + j] = arith.sub(nm[i + j], arith.mul(lm[i], r[j]));
                    _new[i + j] = arith.sub(_new[i + j], arith.mul(low[i], r[j]));
                }
            }

            high = low;
            hm = lm;
            low = _new;
            lm = nm;
        }

        return div(
            PolyExtFieldElem(std::vector<UIntType>(lm.begin(), lm.begin() + degree)), low[0]);
    }

    static inline constexpr PolyExtFieldElem div(
        const PolyExtFieldElem& x, const PolyExtFieldElem& y) noexcept
    {
        return mul(x, inv(y));
    }

    static inline PolyExtFieldElem one() noexcept
    {
        std::vector<UIntType> _one(degree);
        _one[0] = 1;
        return PolyExtFieldElem(std::move(_one));
    }

    static inline PolyExtFieldElem one_mont() noexcept
    {
        std::vector<UIntType> _one(degree);
        _one[0] = arith.one_mont();
        return PolyExtFieldElem(std::move(_one));
    }

    static inline constexpr PolyExtFieldElem zero() noexcept { return PolyExtFieldElem(); }

    template <typename PowUintT>
    static inline constexpr PolyExtFieldElem pow(
        const PolyExtFieldElem& x, const PowUintT& y) noexcept
    {
        auto o = one_mont();
        auto t = x;
        auto p = y;
        while (p > 0)
        {
            if (p & 1)
                o = o * t;
            p >>= 1;
            t = t * t;
        }

        return o;
    }

    static inline constexpr PolyExtFieldElem pow(
        const PolyExtFieldElem& x, const intx::uint<2816>& y) noexcept
    {
        auto o = one_mont();
        auto t = x;

        for (size_t i = 0; i < y.num_words - 1; ++i)
        {
            auto p = y[i];
            for (uint8_t _ = 0; _ < y.word_num_bits; ++_)
            {
                if (p & 1)
                    o = o * t;
                p >>= 1;
                t = t * t;
            }
        }

        auto p = y[y.num_words - 1];
        while (p > 0)
        {
            if (p & 1)
                o = o * t;
            p >>= 1;
            t = t * t;
        }

        return o;
    }

    static inline constexpr PolyExtFieldElem neg(const PolyExtFieldElem& x) noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.neg(x.coeffs[i]);

        return result;
    }

    static inline constexpr bool eq(const PolyExtFieldElem& x, const PolyExtFieldElem& y) noexcept
    {
        for (size_t i = 0; i < degree; ++i)
        {
            if (x.coeffs[i] != y.coeffs[i])
                return false;
        }

        return true;
    }

    //    friend std::ostream& operator<<(std::ostream& os, const PolyExtFieldElem& x)
    //    {
    //        os << "["sv;
    //
    //        if (!x.coeffs.empty())
    //        {
    //            for (size_t i = 0; i < x.coeffs.size() - 1; ++i)
    //                os << "0x"sv << hex(x.coeffs[i]) << ", ";
    //            os << "0x"sv << hex(x.coeffs.back());
    //        }
    //
    //        os << "]"sv;
    //        return os;
    //    }

    PolyExtFieldElem to_mont() const noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.to_mont(this->coeffs[i]);

        return result;
    }

    PolyExtFieldElem from_mont() const noexcept
    {
        PolyExtFieldElem result;

        for (size_t i = 0; i < degree; ++i)
            result.coeffs[i] = arith.from_mont(this->coeffs[i]);

        return result;
    }

    friend PolyExtFieldElem operator*(const PolyExtFieldElem& a, const PolyExtFieldElem& b) noexcept
    {
        return mul(a, b);
    }

    friend PolyExtFieldElem operator*(const PolyExtFieldElem& a, const UIntType& c) noexcept
    {
        return mul(a, c);
    }

    friend PolyExtFieldElem operator*(const UIntType& c, const PolyExtFieldElem& a) noexcept
    {
        return mul(a, c);
    }

    friend PolyExtFieldElem operator-(const PolyExtFieldElem& a, const PolyExtFieldElem& b) noexcept
    {
        return sub(a, b);
    }

    friend PolyExtFieldElem operator+(const PolyExtFieldElem& a, const PolyExtFieldElem& b) noexcept
    {
        return add(a, b);
    }

    friend PolyExtFieldElem operator^(const PolyExtFieldElem& a, const size_t& b) noexcept
    {
        return pow(a, b);
    }

    friend PolyExtFieldElem operator^(const PolyExtFieldElem& a, const UIntType& b) noexcept
    {
        return pow(a, b);
    }

    friend PolyExtFieldElem operator-(const PolyExtFieldElem& a) noexcept { return neg(a); }

    friend bool operator==(const PolyExtFieldElem& a, const PolyExtFieldElem& b) noexcept
    {
        return eq(a, b);
    }

    friend bool operator!=(const PolyExtFieldElem& a, const PolyExtFieldElem& b) noexcept
    {
        return !eq(a, b);
    }
};

}  // namespace evmmax
