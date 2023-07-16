// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <intx/intx.hpp>

namespace evmmax
{

/// The modular arithmetic operations for EVMMAX (EVM Modular Arithmetic Extensions).
template <typename UintT>
class ModArith
{
public:
    const UintT mod;  ///< The modulus.

private:
    const UintT m_r_squared;  ///< R² % mod.

    /// The modulus inversion, i.e. the number N' such that mod⋅N' = 2⁶⁴-1.
    const uint64_t m_mod_inv;

public:
    explicit ModArith(const UintT& modulus) noexcept;

    /// Converts a value to Montgomery form.
    ///
    /// This is done by using Montgomery multiplication mul(x, R²)
    /// what gives aR²R⁻¹ % mod = aR % mod.
    UintT to_mont(const UintT& x) const noexcept;

    /// Converts a value in Montgomery form back to normal value.
    ///
    /// Given the x is the Montgomery form x = aR, the conversion is done by using
    /// Montgomery multiplication mul(x, 1) what gives aRR⁻¹ % mod = a % mod.
    UintT from_mont(const UintT& x) const noexcept;

    /// Performs a Montgomery modular multiplication.
    ///
    /// Inputs must be in Montgomery form: x = aR, y = bR.
    /// This computes Montgomery multiplication xyR⁻¹ % mod what gives aRbRR⁻¹ % mod = abR % mod.
    /// The result (abR) is in Montgomery form.
    UintT mul(const UintT& x, const UintT& y) const noexcept;

    /// Performs a modular addition. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    UintT add(const UintT& x, const UintT& y) const noexcept;

    /// Performs a modular subtraction. It is required that x < mod and y < mod, but x and y may be
    /// but are not required to be in Montgomery form.
    UintT sub(const UintT& x, const UintT& y) const noexcept;
};
}  // namespace evmmax
