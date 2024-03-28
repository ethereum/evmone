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
    typedef BaseFieldConfigT::ValueT ValueT;

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

    static inline constexpr BaseFieldElem add(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.add(e1.value(), e2.value()));
    }

    static inline constexpr BaseFieldElem sub(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.sub(e1.value(), e2.value()));
    }

    static inline constexpr BaseFieldElem mul(
        const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return BaseFieldElem(Fp.mul(e1.value(), e2.value()));
    }

    static inline constexpr BaseFieldElem mul(const BaseFieldElem& e1, const ValueT& s) noexcept
    {
        return BaseFieldElem(Fp.mul(e1.value(), s));
    }

    static inline constexpr bool eq(const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return e1.value() == e2.value();
    }

    static inline constexpr bool neq(const BaseFieldElem& e1, const BaseFieldElem& e2) noexcept
    {
        return e1.value() != e2.value();
    }

    static inline constexpr BaseFieldElem neg(const BaseFieldElem& e) noexcept
    {
        return BaseFieldElem(Fp.sub(ValueT{0}, e.value()));
    }

    inline constexpr BaseFieldElem inv() const noexcept { return inverse(*this); }

    inline constexpr bool is_zero() const noexcept { return m_value == 0; }

    inline constexpr std::string to_string() const noexcept
    {
        return "0x" + hex(Fp.from_mont(m_value));
    }

    static inline constexpr BaseFieldElem one() noexcept
    {
        return BaseFieldElem(BaseFieldConfigT::ONE);
    }

    static inline constexpr BaseFieldElem zero() noexcept { return BaseFieldElem(0); }
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
    typedef FieldConfigT::ValueT ValueT;
    typedef FieldConfigT::BaseFieldT Base;
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

    static inline constexpr ExtFieldElem add(
        const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        CoeffArrT res = e1.coeffs;
        for (size_t i = 0; i < DEGREE; ++i)
            res[i] = ValueT::add(res[i], e2.coeffs[i]);

        return ExtFieldElem(std::move(res));
    }

    static inline constexpr ExtFieldElem sub(
        const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        CoeffArrT res = e1.coeffs;
        for (size_t i = 0; i < DEGREE; ++i)
            res[i] = ValueT::sub(res[i], e2.coeffs[i]);

        return ExtFieldElem(std::move(res));
    }

    static inline constexpr ExtFieldElem mul(const ExtFieldElem& e, const Base& s) noexcept
    {
        CoeffArrT res_arr = e.coeffs;
        for (auto& c : res_arr)
            c = ValueT::mul(c, s);
        return ExtFieldElem(std::move(res_arr));
    }

    static inline constexpr ExtFieldElem mul(
        const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        return multiply(e1, e2);
    }

    static inline constexpr ExtFieldElem neg(const ExtFieldElem& e) noexcept
    {
        CoeffArrT ret;
        for (size_t i = 0; i < DEGREE; ++i)
            ret[i] = ValueT::neg(e.coeffs[i]);

        return ExtFieldElem(std::move(ret));
    }

    static inline constexpr bool eq(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        bool res = true;
        for (size_t i = 0; i < DEGREE && res; ++i)
            res = res && ValueT::eq(e1.coeffs[i], e2.coeffs[i]);

        return res;
    }

    static inline constexpr bool neq(const ExtFieldElem& e1, const ExtFieldElem& e2) noexcept
    {
        return !eq(e1, e2);
    }

    inline constexpr std::string to_string() const noexcept
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
};

template <typename FieldElem>
inline constexpr FieldElem operator+(const FieldElem& e1, const FieldElem& e2) noexcept
{
    return FieldElem::add(e1, e2);
}

template <typename FieldElem>
inline constexpr FieldElem operator+(
    const FieldElem& e1, const typename FieldElem::Base& e2) noexcept
{
    return FieldElem::add(e1, e2);
}

template <typename FieldElem>
inline constexpr FieldElem operator-(const FieldElem& e1, const FieldElem& e2) noexcept
{
    return FieldElem::sub(e1, e2);
}

template <typename FieldElem>
inline constexpr FieldElem operator*(const FieldElem& e1, const FieldElem& e2) noexcept
{
    return FieldElem::mul(e1, e2);
}

template <typename FieldElem>
inline constexpr FieldElem operator-(const FieldElem& e) noexcept
{
    return FieldElem::neg(e);
}

template <typename FieldElem>
inline constexpr bool operator==(const FieldElem& e1, const FieldElem& e2) noexcept
{
    return FieldElem::eq(e1, e2);
}

template <typename FieldElem>
inline constexpr bool operator!=(const FieldElem& e1, const FieldElem& e2) noexcept
{
    return !FieldElem::eq(e1, e2);
}

template <typename FieldElem>
inline constexpr FieldElem operator*(const typename FieldElem::Base& s, const FieldElem& e) noexcept
{
    return FieldElem::mul(e, s);
}

template <typename FieldElem>
inline constexpr FieldElem operator*(const FieldElem& e, const typename FieldElem::Base& s) noexcept
{
    return FieldElem::mul(e, s);
}

template <typename ValueT>
inline constexpr ecc::ProjPoint<ValueT> operator-(const ecc::ProjPoint<ValueT>& p) noexcept
{
    return {p.x, -p.y, p.z};
}

template <typename ValueT>
inline constexpr ecc::JacPoint<ValueT> operator-(const ecc::JacPoint<ValueT>& p) noexcept
{
    return {p.x, -p.y, p.z};
}

template <typename ValueT>
inline constexpr ecc::Point<ValueT> operator-(const ecc::Point<ValueT>& p) noexcept
{
    return {p.x, -p.y};
}
}  // namespace evmmax::ecc
