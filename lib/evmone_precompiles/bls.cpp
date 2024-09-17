#include "bls.hpp"
#include <blst.h>
#include <memory>
#include <optional>
#include <vector>

namespace evmone::crypto::bls
{
namespace
{
/// Offset of the beginning of field element. First 16 bytes must be zero according to spec
/// https://eips.ethereum.org/EIPS/eip-2537#field-elements-encoding
constexpr auto FP_BYTES_OFFSET = 64 - 48;

/// Validates p1 affine point. Checks that point coordinates are from the BLS12-381 field and
/// that the point is on curve. https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-addition
[[nodiscard]] std::optional<blst_p1_affine> validate_p1(
    const uint8_t _x[64], const uint8_t _y[64]) noexcept
{
    constexpr auto is_field_element = [](const uint8_t _p[64]) {
        return intx::be::unsafe::load<intx::uint512>(_p) < BLS_FIELD_MODULUS;
    };

    if (!is_field_element(_x))
        return std::nullopt;
    if (!is_field_element(_y))
        return std::nullopt;

    blst_fp x;
    blst_fp y;
    blst_fp_from_bendian(&x, &_x[FP_BYTES_OFFSET]);
    blst_fp_from_bendian(&y, &_y[FP_BYTES_OFFSET]);

    const blst_p1_affine p0_affine{x, y};
    if (!blst_p1_affine_on_curve(&p0_affine))
        return std::nullopt;

    return p0_affine;
}

/// Validates p2 affine point. Checks that point coordinates are from the BLS12-381 field and
/// that the point is on curve. https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-addition
[[nodiscard]] std::optional<blst_p2_affine> validate_p2(
    const uint8_t _x[128], const uint8_t _y[128]) noexcept
{
    constexpr auto is_field_element = [](const uint8_t _p[128]) {
        return intx::be::unsafe::load<intx::uint512>(_p) < BLS_FIELD_MODULUS &&
               intx::be::unsafe::load<intx::uint512>(&_p[64]) < BLS_FIELD_MODULUS;
    };

    if (!is_field_element(_x))
        return std::nullopt;
    if (!is_field_element(_y))
        return std::nullopt;

    blst_fp x0;
    blst_fp x1;
    blst_fp y0;
    blst_fp y1;
    blst_fp_from_bendian(&x0, &_x[FP_BYTES_OFFSET]);
    blst_fp_from_bendian(&x1, &_x[FP_BYTES_OFFSET + 64]);
    blst_fp_from_bendian(&y0, &_y[FP_BYTES_OFFSET]);
    blst_fp_from_bendian(&y1, &_y[FP_BYTES_OFFSET + 64]);

    const blst_p2_affine p_affine{{x0, x1}, {y0, y1}};
    if (!blst_p2_affine_on_curve(&p_affine))
        return std::nullopt;

    return p_affine;
}

/// Stores fp in 64-bytes array with big endian encoding zero padded.
void store(uint8_t _rx[64], const blst_fp& _x) noexcept
{
    std::memset(_rx, 0, FP_BYTES_OFFSET);
    blst_bendian_from_fp(&_rx[FP_BYTES_OFFSET], &_x);
}

/// Stores fp2 in 128-bytes array with big endian encoding zero padded.
void store(uint8_t _rx[128], const blst_fp2& _x) noexcept
{
    store(_rx, _x.fp[0]);
    store(&_rx[64], _x.fp[1]);
}

}  // namespace

[[nodiscard]] bool g1_add(uint8_t _rx[64], uint8_t _ry[64], const uint8_t _x0[64],
    const uint8_t _y0[64], const uint8_t _x1[64], const uint8_t _y1[64]) noexcept
{
    const auto p0_affine = validate_p1(_x0, _y0);
    const auto p1_affine = validate_p1(_x1, _y1);

    if (!p0_affine.has_value() || !p1_affine.has_value())
        return false;

    blst_p1 p0;
    blst_p1_from_affine(&p0, &*p0_affine);

    blst_p1 out;
    blst_p1_add_or_double_affine(&out, &p0, &*p1_affine);

    blst_p1_affine result;
    blst_p1_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

[[nodiscard]] bool g1_mul(uint8_t _rx[64], uint8_t _ry[64], const uint8_t _x[64],
    const uint8_t _y[64], const uint8_t _c[32]) noexcept
{
    blst_scalar scalar;
    blst_scalar_from_bendian(&scalar, _c);

    const auto p_affine = validate_p1(_x, _y);
    if (!p_affine.has_value())
        return false;

    blst_p1 p;
    blst_p1_from_affine(&p, &*p_affine);

    if (!blst_p1_in_g1(&p))
        return false;

    blst_p1 out;
    blst_p1_mult(&out, &p, scalar.b, 256);

    blst_p1_affine result;
    blst_p1_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

[[nodiscard]] bool g2_add(uint8_t _rx[128], uint8_t _ry[128], const uint8_t _x0[128],
    const uint8_t _y0[128], const uint8_t _x1[128], const uint8_t _y1[128]) noexcept
{
    const auto p0_affine = validate_p2(_x0, _y0);
    const auto p1_affine = validate_p2(_x1, _y1);

    if (!p0_affine.has_value() || !p1_affine.has_value())
        return false;

    blst_p2 p0;
    blst_p2_from_affine(&p0, &*p0_affine);

    blst_p2 out;
    blst_p2_add_or_double_affine(&out, &p0, &*p1_affine);

    blst_p2_affine result;
    blst_p2_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

[[nodiscard]] bool g2_mul(uint8_t _rx[128], uint8_t _ry[128], const uint8_t _x[128],
    const uint8_t _y[128], const uint8_t _c[32]) noexcept
{
    blst_scalar scalar;
    blst_scalar_from_bendian(&scalar, _c);

    const auto p_affine = validate_p2(_x, _y);
    if (!p_affine.has_value())
        return false;

    blst_p2 p;
    blst_p2_from_affine(&p, &*p_affine);

    if (!blst_p2_in_g2(&p))
        return false;

    blst_p2 out;
    blst_p2_mult(&out, &p, scalar.b, 256);

    blst_p2_affine result;
    blst_p2_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

[[nodiscard]] bool g1_msm(
    uint8_t _rx[64], uint8_t _ry[64], const uint8_t* _xycs, size_t size) noexcept
{
    constexpr auto SINGLE_ENTRY_SIZE = (64 * 2 + 32);
    assert(size % SINGLE_ENTRY_SIZE == 0);
    auto npoints = size / SINGLE_ENTRY_SIZE;

    std::vector<blst_p1_affine> p1_affines;
    std::vector<const blst_p1_affine*> p1_affine_ptrs;
    p1_affines.reserve(npoints);
    p1_affine_ptrs.reserve(npoints);

    std::vector<blst_scalar> scalars;
    std::vector<const uint8_t*> scalars_ptrs;
    scalars.reserve(npoints);
    scalars_ptrs.reserve(npoints);

    auto ptr = _xycs;
    for (size_t i = 0; i < npoints; ++i)
    {
        const auto p_affine = validate_p1(ptr, &ptr[64]);
        if (!p_affine.has_value())
            return false;

        if (!blst_p1_affine_in_g1(&*p_affine))
            return false;

        // Point at infinity must be filtered out for BLST library.
        if (blst_p1_affine_is_inf(&*p_affine))
            continue;

        const auto& p = p1_affines.emplace_back(*p_affine);
        p1_affine_ptrs.emplace_back(&p);

        blst_scalar scalar;
        blst_scalar_from_bendian(&scalar, &ptr[128]);
        const auto& s = scalars.emplace_back(scalar);
        scalars_ptrs.emplace_back(s.b);

        ptr += SINGLE_ENTRY_SIZE;
    }

    npoints = p1_affine_ptrs.size();

    if (npoints == 0)
    {
        memset(_rx, 0, 64);
        memset(_ry, 0, 64);
        return true;
    }

    const auto scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(npoints) / sizeof(limb_t);
    const auto scratch_space = std::make_unique_for_overwrite<limb_t[]>(scratch_size);
    blst_p1 out;
    blst_p1s_mult_pippenger(
        &out, p1_affine_ptrs.data(), npoints, scalars_ptrs.data(), 256, scratch_space.get());

    blst_p1_affine result;
    blst_p1_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

[[nodiscard]] bool g2_msm(
    uint8_t _rx[128], uint8_t _ry[128], const uint8_t* _xycs, size_t size) noexcept
{
    constexpr auto SINGLE_ENTRY_SIZE = (128 * 2 + 32);
    assert(size % SINGLE_ENTRY_SIZE == 0);
    auto npoints = size / SINGLE_ENTRY_SIZE;

    std::vector<blst_p2_affine> p2_affines;
    std::vector<const blst_p2_affine*> p2_affine_ptrs;
    p2_affines.reserve(npoints);
    p2_affine_ptrs.reserve(npoints);

    std::vector<blst_scalar> scalars;
    std::vector<const uint8_t*> scalars_ptrs;
    scalars.reserve(npoints);
    scalars_ptrs.reserve(npoints);

    auto ptr = _xycs;
    for (size_t i = 0; i < npoints; ++i)
    {
        const auto p_affine = validate_p2(ptr, &ptr[128]);
        if (!p_affine.has_value())
            return false;

        if (!blst_p2_affine_in_g2(&*p_affine))
            return false;

        // Point at infinity must be filtered out for BLST library.
        if (blst_p2_affine_is_inf(&*p_affine))
            continue;

        const auto& p = p2_affines.emplace_back(*p_affine);
        p2_affine_ptrs.emplace_back(&p);

        blst_scalar scalar;
        blst_scalar_from_bendian(&scalar, &ptr[256]);
        const auto& s = scalars.emplace_back(scalar);
        scalars_ptrs.emplace_back(s.b);

        ptr += SINGLE_ENTRY_SIZE;
    }

    npoints = p2_affine_ptrs.size();

    if (npoints == 0)
    {
        memset(_rx, 0, 128);
        memset(_ry, 0, 128);
        return true;
    }

    const auto scratch_size = blst_p2s_mult_pippenger_scratch_sizeof(npoints) / sizeof(limb_t);
    const auto scratch_space = std::make_unique_for_overwrite<limb_t[]>(scratch_size);
    blst_p2 out;
    blst_p2s_mult_pippenger(
        &out, p2_affine_ptrs.data(), npoints, scalars_ptrs.data(), 256, scratch_space.get());

    blst_p2_affine result;
    blst_p2_to_affine(&result, &out);
    store(_rx, result.x);
    store(_ry, result.y);

    return true;
}

}  // namespace evmone::crypto::bls
