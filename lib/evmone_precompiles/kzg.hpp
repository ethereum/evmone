// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "sha256.hpp"
#include <intx/intx.hpp>

namespace evmone::crypto
{
using namespace intx::literals;

/// Length (in bytes) of the versioned hash (based on SHA256).
constexpr auto VERSIONED_HASH_SIZE = SHA256_HASH_SIZE;

/// The KZG version number of the versioned hash.
constexpr std::byte VERSIONED_HASH_VERSION_KZG{0x01};

/// An EIP-4844 parameter.
constexpr auto FIELD_ELEMENTS_PER_BLOB = 4096_u256;

/// Scalar field modulus of BLS12-381.
constexpr auto BLS_MODULUS =
    52435875175126190479447740508185965837690552500527637822603658699938581184513_u256;

/// Number of significant bits of the BLS_MODULUS.
constexpr size_t BLS_MODULUS_BITS = 255;
static_assert((BLS_MODULUS >> BLS_MODULUS_BITS) == 0);

bool kzg_verify_proof(const std::byte versioned_hash[VERSIONED_HASH_SIZE], const std::byte z[32],
    const std::byte y[32], const std::byte commitment[48], const std::byte proof[48]) noexcept;
}  // namespace evmone::crypto
