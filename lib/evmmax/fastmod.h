#ifndef FASTMOD_H
#define FASTMOD_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stdint.h>
#else
#include <cstdint>
#endif

#ifndef __cplusplus
#define FASTMOD_API static inline
#else
// In C++ we mark all the functions inline.
// If C++14 relaxed constexpr is supported we use constexpr so functions
// can be used at compile-time.
#if __cpp_constexpr >= 201304 && !defined(_MSC_VER)
// visual studio does not like constexpr
#define FASTMOD_API constexpr
#define FASTMOD_CONSTEXPR constexpr
#else
#define FASTMOD_API inline
#define FASTMOD_CONSTEXPR
#endif
#endif

#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifdef __cplusplus
namespace fastmod
{
#endif

#ifdef _MSC_VER

// __umulh is only available on x64, ARM64 mode under Visual Studio: don't compile in
// 32-bit mode!
FASTMOD_API uint64_t mul128_u32(uint64_t lowbits, uint32_t d)
{
    return __umulh(lowbits, d);
}
FASTMOD_API uint64_t mul128_from_u64(uint64_t lowbits, uint64_t d)
{
    return __umulh(lowbits, d);
}
FASTMOD_API uint64_t mul128_s32(uint64_t lowbits, int32_t d)
{
    if (d < 0)
    {
        return mul128_from_u64(lowbits, (int64_t)d) - lowbits;
    }
    return mul128_u32(lowbits, d);
}

// Need _udiv128 to calculate the magic number (maps to x86 64-bit div)
#if defined(_M_AMD64) && (_MSC_VER >= 1923)
// This is for the 64-bit functions.
// Visual Studio lacks support for 128-bit integers so they simulated are using
// multiword arithmatic and VS specific intrinsics.

FASTMOD_API uint64_t add128_u64(uint64_t M_hi, uint64_t M_lo, uint64_t addend, uint64_t* sum_hi)
{
    uint64_t sum_lo;

    bool carry = _addcarry_u64(0, M_lo, addend, &sum_lo);
    _addcarry_u64(carry, M_hi, 0, sum_hi);  // Encourages 'adc'

    return sum_lo;
}

FASTMOD_API uint64_t div128_u64(
    uint64_t dividend_hi, uint64_t dividend_lo, uint64_t divisor, uint64_t* quotient_hi)
{
    *quotient_hi = dividend_hi / divisor;
    uint64_t remainder_hi = dividend_hi % divisor;

    // When long div starts to consider the low dividend,
    // the high part would have became its remainder.
    // Prevents an arithmetic exception when _udiv128 calculates a >64-bit quotient
    uint64_t remainder;  // Discard
    return _udiv128(remainder_hi, dividend_lo, divisor, &remainder);
}

// Multiplies the 128-bit integer by d and returns the lower 128-bits of the product
FASTMOD_API uint64_t mul128_u64_lo(uint64_t M_hi, uint64_t M_lo, uint64_t d, uint64_t* product_hi)
{
    uint64_t lowbits_hi;
    uint64_t lowbits_lo = _umul128(M_lo, d, &lowbits_hi);

    *product_hi = lowbits_hi + (M_hi * d);

    return lowbits_lo;
}

// Multiplies the 128-bit integer by d and returns the highest 64-bits of the product
FASTMOD_API uint64_t mul128_u64_hi(uint64_t lowbits_hi, uint64_t lowbits_lo, uint64_t d)
{
    uint64_t bottomHalf_hi = __umulh(lowbits_lo, d);

    uint64_t topHalf_hi;
    uint64_t topHalf_lo = _umul128(lowbits_hi, d, &topHalf_hi);

    uint64_t bothHalves_hi;
    add128_u64(topHalf_hi, topHalf_lo, bottomHalf_hi, &bothHalves_hi);

    return bothHalves_hi;
}

FASTMOD_API bool isgreater_u128(uint64_t a_hi, uint64_t a_low, uint64_t b_hi, uint64_t b_low)
{
    // Only when low is greater, high equality should return true
    uint64_t discard;
    bool borrowWhenEql = _subborrow_u64(0, b_low, a_low, &discard);

    // borrow(b - (a + C_in)) = C_in? (a >= b) : (a > b)
    return _subborrow_u64(borrowWhenEql, b_hi, a_hi, &discard);
}

#endif  // End MSVC 64-bit support
#else   // _MSC_VER NOT defined

FASTMOD_API uint64_t mul128_u32(uint64_t lowbits, uint32_t d)
{
    return ((__uint128_t)lowbits * d) >> 64;
}
FASTMOD_API uint64_t mul128_from_u64(uint64_t lowbits, uint64_t d)
{
    return ((__uint128_t)lowbits * d) >> 64;
}
FASTMOD_API uint64_t mul128_s32(uint64_t lowbits, int32_t d)
{
    if (d < 0)
    {
        return mul128_from_u64(lowbits, (int64_t)d) - lowbits;
    }
    return mul128_u32(lowbits, d);
}

// This is for the 64-bit functions.
FASTMOD_API uint64_t mul128_u64(__uint128_t lowbits, uint64_t d)
{
    __uint128_t bottom_half = (lowbits & UINT64_C(0xFFFFFFFFFFFFFFFF)) * d;  // Won't overflow
    bottom_half >>= 64;  // Only need the top 64 bits, as we'll shift the lower half away;
    __uint128_t top_half = (lowbits >> 64) * d;
    __uint128_t both_halves = bottom_half + top_half;  // Both halves are already shifted down by 64
    both_halves >>= 64;                                // Get top half of both_halves
    return (uint64_t)both_halves;
}

#endif  // _MSC_VER

/**
 * Unsigned integers.
 * Usage:
 *  uint32_t d = ... ; // divisor, should be non-zero
 *  uint64_t M = computeM_u32(d); // do once
 *  fastmod_u32(a,M,d) is a % d for all 32-bit a.
 *
 **/

// M = ceil( (1<<64) / d ), d > 0
FASTMOD_API uint64_t computeM_u32(uint32_t d)
{
    return UINT64_C(0xFFFFFFFFFFFFFFFF) / d + 1;
}

// fastmod computes (a % d) given precomputed M
FASTMOD_API uint32_t fastmod_u32(uint32_t a, uint64_t M, uint32_t d)
{
    uint64_t lowbits = M * a;
    return (uint32_t)(mul128_u32(lowbits, d));
}

// fastdiv computes (a / d) given precomputed M for d>1
FASTMOD_API uint32_t fastdiv_u32(uint32_t a, uint64_t M)
{
    return (uint32_t)(mul128_u32(M, a));
}

// given precomputed M, is_divisible checks whether n % d == 0
FASTMOD_API bool is_divisible(uint32_t n, uint64_t M)
{
    return n * M <= M - 1;
}

/**
 * signed integers
 * Usage:
 *  int32_t d = ... ; // should be non-zero and between [-2147483647,2147483647]
 *  int32_t positive_d = d < 0 ? -d : d; // absolute value
 *  uint64_t M = computeM_s32(d); // do once
 *  fastmod_s32(a,M,positive_d) is a % d for all 32-bit a.
 **/

// M = floor( (1<<64) / d ) + 1
// you must have that d is different from 0 and -2147483648
// if d = -1 and a = -2147483648, the result is undefined
FASTMOD_API uint64_t computeM_s32(int32_t d)
{
    if (d < 0)
        d = -d;
    return UINT64_C(0xFFFFFFFFFFFFFFFF) / d + 1 + ((d & (d - 1)) == 0 ? 1 : 0);
}

// fastmod computes (a % d) given precomputed M,
// you should pass the absolute value of d
FASTMOD_API int32_t fastmod_s32(int32_t a, uint64_t M, int32_t positive_d)
{
    uint64_t lowbits = M * a;
    int32_t highbits = (int32_t)mul128_u32(lowbits, positive_d);
    return highbits - ((positive_d - 1) & (a >> 31));
}

// fastdiv computes (a / d) given a precomputed M, assumes that d must not
// be one of -1, 1, or -2147483648
FASTMOD_API int32_t fastdiv_s32(int32_t a, uint64_t M, int32_t d)
{
    uint64_t highbits = mul128_s32(M, a);
    highbits += (a < 0 ? 1 : 0);
    if (d < 0)
        return -(int32_t)(highbits);
    return (int32_t)(highbits);
}

// What follows is the 64-bit functions.
// They may not be faster than what the compiler can produce.

#ifndef _MSC_VER
// No __uint128_t in VS, so they have to use a diffrent method.

FASTMOD_API __uint128_t computeM_u64(uint64_t d)
{
    // what follows is just ((__uint128_t)0 - 1) / d) + 1 spelled out
    __uint128_t M = UINT64_C(0xFFFFFFFFFFFFFFFF);
    M <<= 64;
    M |= UINT64_C(0xFFFFFFFFFFFFFFFF);
    M /= d;
    M += 1;
    return M;
}

FASTMOD_API uint64_t fastmod_u64(uint64_t a, __uint128_t M, uint64_t d)
{
    __uint128_t lowbits = M * a;
    return mul128_u64(lowbits, d);
}

FASTMOD_API uint64_t fastdiv_u64(uint64_t a, __uint128_t M)
{
    return mul128_u64(M, a);
}

// given precomputed M, is_divisible checks whether n % d == 0
FASTMOD_API bool is_divisible_u64(uint64_t n, __uint128_t M)
{
    return n * M <= M - 1;
}

#elif defined(_MSC_VER) && defined(_M_AMD64) && (_MSC_VER >= 1923)
// Visual Studio lacks support for 128-bit integers
// so they simulated are using multiword arithmatic
// and VS specific intrinsics.

// Using a struct in the multiword arithmetic functions produces
// worse asm output but isn't that bad for public functions

typedef struct
{
    uint64_t low;
    uint64_t hi;
} fastmod_u128_t;

FASTMOD_API fastmod_u128_t computeM_u64(uint64_t d)
{
    // UINT128MAX / d
    uint64_t magic_quotient_hi;
    uint64_t magic_quotient_lo = div128_u64(~UINT64_C(0), ~UINT64_C(0), d, &magic_quotient_hi);

    // quotient_u128 + 1
    fastmod_u128_t M;
    M.low = add128_u64(magic_quotient_hi, magic_quotient_lo, 1, &M.hi);
    return M;
}

// computes (a % d) given precomputed M
FASTMOD_API uint64_t fastmod_u64(uint64_t a, fastmod_u128_t M, uint64_t d)
{
    uint64_t lowbits_hi;
    uint64_t lowbits_lo = mul128_u64_lo(M.hi, M.low, a, &lowbits_hi);

    return mul128_u64_hi(lowbits_hi, lowbits_lo, d);
}

// computes (a / d) given precomputed M for d>1
FASTMOD_API uint64_t fastdiv_u64(uint64_t a, fastmod_u128_t M)
{
    return mul128_u64_hi(M.hi, M.low, a);
}

// given precomputed M, is_divisible checks whether n % d == 0
FASTMOD_API bool is_divisible_u64(uint64_t n, fastmod_u128_t M)
{
    uint64_t lowBits_hi;
    uint64_t lowBits_low = mul128_u64_lo(M.hi, M.low, n, &lowBits_hi);

    uint64_t Mdec_low, Mdec_hi;
    bool borrow_hi = _subborrow_u64(0, M.low, 1, &Mdec_low);
    _subborrow_u64(borrow_hi, M.hi, 0, &Mdec_hi);

    // n * M <= M - 1
    return !isgreater_u128(lowBits_hi, lowBits_low, Mdec_hi, Mdec_low);
}


// End of the 64-bit functions

#endif  // #ifndef _MSC_VER

#ifdef __cplusplus

template <uint32_t d>
FASTMOD_API uint32_t fastmod(uint32_t x)
{
    FASTMOD_CONSTEXPR uint64_t v = computeM_u32(d);
    return fastmod_u32(x, v, d);
}
template <uint32_t d>
FASTMOD_API uint32_t fastdiv(uint32_t x)
{
    FASTMOD_CONSTEXPR uint64_t v = computeM_u32(d);
    return fastdiv_u32(x, v);
}
template <int32_t d>
FASTMOD_API int32_t fastmod(int32_t x)
{
    FASTMOD_CONSTEXPR uint64_t v = computeM_s32(d);
    return fastmod_s32(x, v, d);
}
template <int32_t d>
FASTMOD_API int32_t fastdiv(int32_t x)
{
    FASTMOD_CONSTEXPR uint64_t v = computeM_s32(d);
    return fastdiv_s32(x, v, d);
}

}  // fastmod
#endif

#undef FASTMOD_API
#undef FASTMOD_CONSTEXPR

#endif  // FASTMOD_H
