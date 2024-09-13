#include "bls.hpp"
#include <blst.h>
#include <optional>

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

}  // namespace evmone::crypto::bls
