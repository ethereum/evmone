// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>

namespace evmmax::ecc
{
// Implements computations over base field defined by prime number.
// Wraps around ModArith struct and implements additional functions needed for pairing.
// It is a template struct which can be reused for different pairing implementations.
template <typename BaseFieldConfigT>
struct BaseFieldElem
{
    typedef typename BaseFieldConfigT::ValueT ValueT;

private:
    static constexpr ModArith<ValueT> Fp = BaseFieldConfigT::MOD_ARITH;

    ValueT m_value;

public:
    constexpr BaseFieldElem() noexcept {}

    explicit constexpr BaseFieldElem(const ValueT& v) noexcept : m_value(v) {}
    explicit constexpr BaseFieldElem(const ValueT&& v) noexcept : m_value(v) {}

    static constexpr inline BaseFieldElem from_int(const ValueT& v) noexcept
    {
        return BaseFieldElem(Fp.to_mont(v));
    }

    constexpr const ValueT& value() const noexcept { return m_value; }

    inline BaseFieldElem inv() const noexcept { return inverse(*this); }

    inline constexpr bool is_zero() const noexcept { return m_value == 0; }

    inline std::string to_string() const noexcept { return "0x" + hex(Fp.from_mont(m_value)); }

    static inline constexpr BaseFieldElem one() noexcept
    {
        return BaseFieldElem(BaseFieldConfigT::ONE);
    }

    static inline constexpr BaseFieldElem zero() noexcept { return BaseFieldElem(0); }

    friend constexpr BaseFieldElem operator+(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.add(e1.value(), e2.value()));
    }

    friend constexpr BaseFieldElem operator-(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.sub(e1.value(), e2.value()));
    }

    friend constexpr BaseFieldElem operator*(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.mul(e1.value(), e2.value()));
    }

    friend constexpr BaseFieldElem operator-(const BaseFieldElem& e) noexcept
    {
        return BaseFieldElem(Fp.sub(ValueT{0}, e.value()));
    }

    friend constexpr bool operator==(const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return e1.value() == e2.value();
    }

    friend constexpr bool operator!=(const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return e1.value() != e2.value();
    }
};

template <typename FieldElem>
FieldElem inverse(const FieldElem& e);

template <typename FieldElem>
FieldElem multiply(const FieldElem& a, const FieldElem& b);

// Implements extension field over the base field or other extension fields.
// It is a template struct which can be reused for different pairing implementations.
template <typename FieldConfigT>
struct ExtFieldElem
{
    typedef typename FieldConfigT::ValueT ValueT;
    typedef typename FieldConfigT::BaseFieldT Base;
    static constexpr auto DEGREE = FieldConfigT::DEGREE;
    using CoeffArrT = std::array<ValueT, DEGREE>;
    CoeffArrT coeffs;

    explicit constexpr ExtFieldElem() noexcept
    {
        for (size_t i = 0; i < DEGREE; ++i)
            coeffs[i] = ValueT();
    }

    explicit constexpr ExtFieldElem(CoeffArrT cs) noexcept : coeffs(cs) {}

    inline constexpr ExtFieldElem conjugate() const noexcept
    {
        CoeffArrT res = this->coeffs;

        for (size_t i = 1; i < DEGREE; i += 2)
            res[i] = -res[i];

        return ExtFieldElem(res);
    }

    inline std::string to_string() const noexcept
    {
        std::string res;
        for (const auto& c : coeffs)
            res += c.to_string() + ", ";
        return "[" + res.substr(0, res.size() - 2) + "]";
    }

    static inline constexpr ExtFieldElem one() noexcept
    {
        std::array<ValueT, DEGREE> v;
        v[0] = ValueT::one();
        for (size_t i = 1; i < DEGREE; ++i)
            v[i] = ValueT();

        return ExtFieldElem(v);
    }

    static inline constexpr ExtFieldElem zero() noexcept
    {
        std::array<ValueT, DEGREE> v;
        for (size_t i = 0; i < DEGREE; ++i)
            v[i] = ValueT();

        return ExtFieldElem(v);
    }

    inline constexpr ExtFieldElem inv() const noexcept { return inverse(*this); }

    friend constexpr ExtFieldElem operator+(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        CoeffArrT res = e1.coeffs;
        for (size_t i = 0; i < DEGREE; ++i)
            res[i] = res[i] + e2.coeffs[i];

        return ExtFieldElem(std::move(res));
    }

    friend constexpr ExtFieldElem operator-(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        CoeffArrT res = e1.coeffs;
        for (size_t i = 0; i < DEGREE; ++i)
            res[i] = res[i] - e2.coeffs[i];

        return ExtFieldElem(std::move(res));
    }

    friend constexpr ExtFieldElem operator*(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        return multiply(e1, e2);
    }

    friend constexpr ExtFieldElem operator-(const ExtFieldElem& e) noexcept
    {
        CoeffArrT ret;
        for (size_t i = 0; i < DEGREE; ++i)
            ret[i] = -e.coeffs[i];

        return ExtFieldElem(std::move(ret));
    }

    friend constexpr bool operator==(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        bool res = true;
        for (size_t i = 0; i < DEGREE && res; ++i)
            res = res && (e1.coeffs[i] == e2.coeffs[i]);

        return res;
    }

    friend constexpr bool operator!=(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        return !(e1 == e2);
    }

    friend constexpr ExtFieldElem operator*(
        const ExtFieldElem& e, const typename ExtFieldElem::Base& s) noexcept
    {
        CoeffArrT res_arr = e.coeffs;
        for (auto& c : res_arr)
            c = c * s;
        return ExtFieldElem(std::move(res_arr));
    }

    friend constexpr ExtFieldElem operator*(
        const typename ExtFieldElem::Base& s, const ExtFieldElem& e) noexcept
    {
        return e * s;
    }
};

}  // namespace evmmax::ecc
