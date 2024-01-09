// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <memory>

namespace evmmax
{

using intx::uint256;

struct EXMMAXModStateInterface;

/// Ephemeral EVMMAX (EVM Modular Arithmetic Extensions) state
class EVMMAXState
{
    typedef std::unordered_map<evmc::bytes32, std::unique_ptr<EXMMAXModStateInterface>> ModulusMap;
    ModulusMap mods;  ///< Map of initialized and available moduluses.
    ModulusMap::const_iterator active_mod = mods.end();  ///< Current active modulus

    /// Validates that memory used by EVMMAX state does not exceed a predefined limit.
    [[nodiscard]] bool validate_memory_usage(size_t val_size, size_t num_val) noexcept;

public:
    /// Create new modulus and activates it. In case the modulus already exists, activates it.
    /// Deducts gas accordingly.
    ///
    /// \param gas_left Amount of gas before calling. Is modified by `setupx`
    /// \param mod_id Modulus identifier
    /// \param mod_ptr Modulus big endian value memory pointer
    /// \param mod_size Modulus size in bytes
    /// \param vals_used Number of needed value slots
    /// \return Status code.
    [[nodiscard]] evmc_status_code setupx(int64_t& gas_left, const uint256& mod_id,
        const uint8_t* mod_ptr, size_t mod_size, size_t vals_used) noexcept;

    /// Loads EVMMAX values into EVM memory. Deducts gas accordingly.
    /// Converts to the Montgomery form
    [[nodiscard]] evmc_status_code loadx(
        int64_t& gas_left, uint8_t* out_ptr, size_t val_idx, size_t num_vals) noexcept;

    /// Stores EVM memory into EVMMAX value slots. Deducts gas accordingly.
    /// Converts from the Montgomery form
    [[nodiscard]] evmc_status_code storex(
        int64_t& gas_left, const uint8_t* in_ptr, size_t dst_val_idx, size_t num_vals) noexcept;

    /// Computes modular addition. Deducts gas accordingly. Operates on active modulus.
    ///
    /// (x + y) % active_modulus.
    /// Gets inputs from values slots under indexes `x_idx` and `y_idx`.
    /// Saves result in value slot under index `dst_idx`
    [[nodiscard]] evmc_status_code addmodx(
        int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept;

    /// Computes modular subtraction. Deducts gas accordingly. Operates on active modulus.
    ///
    /// (x - y) % active_modulus.
    /// Gets inputs from values slots under indexes `x_idx` and `y_idx`.
    /// Saves result in value slot under index `dst_idx`
    [[nodiscard]] evmc_status_code submodx(
        int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept;

    /// Computes modular multiplication. Deducts gas accordingly. Operates on active modulus.
    ///
    /// (x * y) % active_modulus.
    /// Gets inputs from values slots under indexes `x_idx` and `y_idx`.
    /// Saves result in value slot under index `dst_idx`
    [[nodiscard]] evmc_status_code mulmodx(
        int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept;

    /// Checks that modulus with `mod_id` exists.
    [[nodiscard]] bool exists(const uint256& mod_id) const noexcept;

    /// Returns active modulus size multiplier.
    /// Size (expressed in multiples of 8 bytes) needed to represent modulus.
    [[nodiscard]] size_t active_mod_value_size_multiplier() const noexcept;

    void clear() noexcept;

    explicit EVMMAXState() noexcept;
    virtual ~EVMMAXState();
};

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
