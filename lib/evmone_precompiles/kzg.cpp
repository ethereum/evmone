// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "kzg.hpp"
#include <blst.h>
#include <algorithm>
#include <optional>
#include <span>

namespace evmone::crypto
{
namespace
{
/// The field element 1 in Montgomery form.
constexpr blst_fp ONE = {0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba,
    0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493};

/// The negation of the subgroup G1 generator -[1]₁ (Jacobian coordinates in Montgomery form).
constexpr blst_p1 G1_GENERATOR_NEGATIVE = {
    {0x5cb38790fd530c16, 0x7817fc679976fff5, 0x154f95c7143ba1c1, 0xf0ae6acdf3d0e747,
        0xedce6ecc21dbf440, 0x120177419e0bfb75},
    {0xff526c2af318883a, 0x92899ce4383b0270, 0x89d7738d9fa9d055, 0x12caf35ba344c12a,
        0x3cff1b76964b5317, 0x0e44d2ede9774430},
    ONE};

/// The negation of the subgroup G2 generator -[1]₂ (Jacobian coordinates in Montgomery form).
constexpr blst_p2 G2_GENERATOR_NEGATIVE{
    {{{0xf5f28fa202940a10, 0xb3f5fb2687b4961a, 0xa1a893b53e2ae580, 0x9894999d1a3caee9,
          0x6f67b7631863366b, 0x058191924350bcd7},
        {0xa5a9c0759e23f606, 0xaaa0c59dbccd60c3, 0x3bb17e18e2867806, 0x1b1ab6cc8541b367,
            0xc2b6ed0ef2158547, 0x11922a097360edf3}}},
    {{{0x6d8bf5079fb65e61, 0xc52f05df531d63a5, 0x7f4a4d344ca692c9, 0xa887959b8577c95f,
          0x4347fe40525c8734, 0x197d145bbaff0bb5},
        {0x0c3e036d209afa4e, 0x0601d8f4863f9e23, 0xe0832636bacc0a84, 0xeb2def362a476f84,
            0x64044f659f0ee1e9, 0x0ed54f48d5a1caa7}}},
    {{ONE, {}}}};

/// The point from the G2 series, index 1 of the Ethereum KZG trusted setup,
/// i.e. [s]₂ where s is the trusted setup's secret.
/// Affine coordinates in Montgomery form.
/// The original value in compressed form (y-parity bit and Fp2 x coordinate)
/// is the ["g2_monomial"][1] of the JSON object found at
/// https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json#L8200
constexpr blst_p2_affine KZG_SETUP_G2_1{
    {{{0x6120a2099b0379f9, 0xa2df815cb8210e4e, 0xcb57be5577bd3d4f, 0x62da0ea89a0c93f8,
          0x02e0ee16968e150d, 0x171f09aea833acd5},
        {0x11a3670749dfd455, 0x04991d7b3abffadc, 0x85446a8e14437f41, 0x27174e7b4e76e3f2,
            0x7bfa6dd397f60a20, 0x02fcc329ac07080f}}},
    {{{0xaa130838793b2317, 0xe236dd220f891637, 0x6502782925760980, 0xd05c25f60557ec89,
          0x6095767a44064474, 0x185693917080d405},
        {0x549f9e175b03dc0a, 0x32c0c95a77106cfe, 0x64a74eae5705d080, 0x53deeaf56659ed9e,
            0x09a1d368508afb93, 0x12cf3a4525b5e9bd}}}};

/// Load and validate an element from the group order field.
std::optional<blst_scalar> validate_scalar(std::span<const std::byte, 32> b) noexcept
{
    blst_scalar v;
    blst_scalar_from_bendian(&v, reinterpret_cast<const uint8_t*>(b.data()));
    return blst_scalar_fr_check(&v) ? std::optional{v} : std::nullopt;
}

/// Uncompress and validate a point from G1 subgroup.
std::optional<blst_p1_affine> validate_G1(std::span<const std::byte, 48> b) noexcept
{
    blst_p1_affine r;
    if (blst_p1_uncompress(&r, reinterpret_cast<const uint8_t*>(b.data())) != BLST_SUCCESS)
        return std::nullopt;

    // Subgroup check is required by the spec but there are no test vectors
    // with points outside G1 which would satisfy the final pairings check.
    if (!blst_p1_affine_in_g1(&r))
        return std::nullopt;
    return r;
}

/// Add two points from E1 and convert the result to affine form.
/// The conversion to affine is very costly so use only if the affine of the result is needed.
blst_p1_affine add_or_double(const blst_p1_affine& p, const blst_p1& q) noexcept
{
    blst_p1 r;
    blst_p1_add_or_double_affine(&r, &q, &p);
    blst_p1_affine ra;
    blst_p1_to_affine(&ra, &r);
    return ra;
}

blst_p1 mult(const blst_p1& p, const blst_scalar& v) noexcept
{
    blst_p1 r;
    blst_p1_mult(&r, &p, v.b, BLS_MODULUS_BITS);
    return r;
}

/// Add two points from E2 and convert the result to affine form.
/// The conversion to affine is very costly so use only if the affine of the result is needed.
blst_p2_affine add_or_double(const blst_p2_affine& p, const blst_p2& q) noexcept
{
    blst_p2 r;
    blst_p2_add_or_double_affine(&r, &q, &p);
    blst_p2_affine ra;
    blst_p2_to_affine(&ra, &r);
    return ra;
}

blst_p2 mult(const blst_p2& p, const blst_scalar& v) noexcept
{
    blst_p2 r;
    blst_p2_mult(&r, &p, v.b, BLS_MODULUS_BITS);
    return r;
}

bool pairings_verify(
    const blst_p1_affine& a1, const blst_p1_affine& b1, const blst_p2_affine& b2) noexcept
{
    blst_fp12 left;
    blst_aggregated_in_g1(&left, &a1);
    blst_fp12 right;
    blst_miller_loop(&right, &b2, &b1);
    return blst_fp12_finalverify(&left, &right);
}
}  // namespace

bool kzg_verify_proof(const std::byte versioned_hash[VERSIONED_HASH_SIZE], const std::byte z[32],
    const std::byte y[32], const std::byte commitment[48], const std::byte proof[48]) noexcept
{
    std::byte computed_versioned_hash[32];
    sha256(computed_versioned_hash, commitment, 48);
    computed_versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    if (!std::ranges::equal(std::span{versioned_hash, 32}, computed_versioned_hash))
        return false;

    // Load and validate scalars z and y.
    // TODO(C++26): The span construction can be done as std::snap(z, std::c_<32>).
    const auto zz = validate_scalar(std::span<const std::byte, 32>{z, 32});
    if (!zz)
        return false;
    const auto yy = validate_scalar(std::span<const std::byte, 32>{y, 32});
    if (!yy)
        return false;

    // Uncompress and validate the points C (representing the polynomial commitment)
    // and Pi (representing the proof). They both are valid to be points at infinity
    // when they prove a commitment to a constant polynomial,
    // see https://hackmd.io/@kevaundray/kzg-is-zero-proof-sound
    const auto C = validate_G1(std::span<const std::byte, 48>{commitment, 48});
    if (!C)
        return false;
    const auto Pi = validate_G1(std::span<const std::byte, 48>{proof, 48});
    if (!Pi)
        return false;

    // Compute -Y as [y * -1]₁.
    const auto neg_Y = mult(G1_GENERATOR_NEGATIVE, *yy);

    // Compute C - Y. It can happen that C == -Y so doubling may be needed.
    const auto C_sub_Y = add_or_double(*C, neg_Y);

    // Compute -Z as [z * -1]₂.
    const auto neg_Z = mult(G2_GENERATOR_NEGATIVE, *zz);

    // Compute X - Z which is [s - z]₂.
    const auto X_sub_Z = add_or_double(KZG_SETUP_G2_1, neg_Z);

    // e(C - [y]₁, [1]₂) =? e(Pi, [s - z]₂)
    return pairings_verify(C_sub_Y, *Pi, X_sub_Z);
}
}  // namespace evmone::crypto
