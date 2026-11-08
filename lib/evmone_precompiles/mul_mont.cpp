// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2026 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "modarith.hpp"
#include "mulmod.hpp"

#ifdef __x86_64__

// The Montgomery multiplication for 4-word operands using MULX (BMI2) and ADCX/ADOX (ADX).
//
// Coarsely Integrated Operand Scanning (CIOS): each word y[i] adds the product row x[]⋅y[i]
// to the accumulator, then the reduction row q⋅m[] with q = t[0]⋅m_inv zeroes the lowest word,
// which is dropped. Each row is a single asm statement running two carry chains: the low halves
// of the products are added on CF (ADCX), the high halves on OF (ADOX). The compiler allocates
// the accumulator words (the rotation costs no moves) and computes q, loads and stores. The final
// conditional subtraction is also asm: compilers turn the borrow into a register before the select.
//
// The accumulator stays below 2m (below R + m for the almost Montgomery multiplication with inputs
// below R), so it takes 5 words with the top word at most 1, and with the product added 6 words.
// For m < 2²⁵⁵ (sparse) the accumulator is below 2²⁵⁶ and, with the product added, below 2³²⁰:
// one word less.
//
// The high half of a 64-bit product is at most 2⁶⁴ - 2, so the last row's high half absorbs
// the pending CF carry before it is added on OF.

namespace evmone::crypto
{
namespace
{
// The asm scratch outputs are not const: clang-tidy does not see asm outputs as modifications.
// NOLINTBEGIN(hicpp-no-assembler,misc-const-correctness)
// clang-format off

/// Adds src[off]⋅rdx to the accumulator: the low half to dl on CF, the high half to dh on OF.
#define MULX_ADD(off, src, dl, dh)                   \
    "mulxq " #off "(%[" #src "]), %[lo], %[hi]\n\t"  \
    "adcxq %[lo], %[" #dl "]\n\t"                    \
    "adoxq %[hi], %[" #dh "]\n\t"

/// Adds src[off]⋅rdx as MULX_ADD() and the pending CF carry to the high half before it is added.
/// The zero register z keeps zero.
#define MULX_ADD_LAST(off, src, dl, dh, z)           \
    "mulxq " #off "(%[" #src "]), %[lo], %[hi]\n\t"  \
    "adcxq %[lo], %[" #dl "]\n\t"                    \
    "adcxq %[" #z "], %[hi]\n\t"                     \
    "adoxq %[hi], %[" #dh "]\n\t"

/// Adds src[0..3]⋅rdx to the accumulator a0..a4, leaving the OF carry pending to the next word.
/// The zero register z keeps zero and CF = OF = 0 on entry.
#define MULX_ADD_ROW4(src, z)                                                    \
    MULX_ADD(0, src, a0, a1) MULX_ADD(8, src, a1, a2) MULX_ADD(16, src, a2, a3) \
        MULX_ADD_LAST(24, src, a3, a4, z)

// clang-format on

/// The words of a W-word operand, for asm memory operands.
template <size_t W = 4>
using Words = uint64_t[W];

template <size_t W = 4>
[[gnu::always_inline]] inline const Words<W>& words(const uint64_t* p) noexcept
{
    return *reinterpret_cast<const Words<W>*>(p);
}

/// Sets the accumulator a0..a4 to x[]⋅y0.
[[gnu::always_inline]] inline void first_row(uint64_t& a0, uint64_t& a1, uint64_t& a2, uint64_t& a3,
    uint64_t& a4, const Words<>& x, uint64_t y0) noexcept
{
    uint64_t lo = 0;
    asm("mulxq (%[x]), %[a0], %[a1]\n\t"
        "mulxq 8(%[x]), %[lo], %[a2]\n\t"
        "addq %[lo], %[a1]\n\t"
        "mulxq 16(%[x]), %[lo], %[a3]\n\t"
        "adcq %[lo], %[a2]\n\t"
        "mulxq 24(%[x]), %[lo], %[a4]\n\t"
        "adcq %[lo], %[a3]\n\t"
        "adcq $0, %[a4]"
        : [a0] "=&r"(a0), [a1] "=&r"(a1), [a2] "=&r"(a2), [a3] "=&r"(a3), [a4] "=&r"(a4),
        [lo] "=&r"(lo)
        : [x] "r"(&x), "d"(y0), "m"(x)
        : "cc");
}

/// Adds x[]⋅yi to the accumulator a0..a4, the carry word goes to a5.
[[gnu::always_inline]] inline void product_row(uint64_t& a0, uint64_t& a1, uint64_t& a2,
    uint64_t& a3, uint64_t& a4, uint64_t& a5, const Words<>& x, uint64_t yi) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("xorl %k[a5], %k[a5]\n\t" MULX_ADD_ROW4(x, a5) "adoxq %[a5], %[a5]"
        : [a0] "+r"(a0), [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "+r"(a4), [a5] "=&r"(a5),
        [lo] "=&r"(lo), [hi] "=&r"(hi)
        : [x] "r"(&x), "d"(yi), "m"(x)
        : "cc");
}

/// Adds q⋅m[] to the accumulator a0..a5, a0 becomes 0.
[[gnu::always_inline]] inline void reduce_row(uint64_t& a0, uint64_t& a1, uint64_t& a2,
    uint64_t& a3, uint64_t& a4, uint64_t& a5, const Words<>& m, uint64_t q) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("xorl %k[lo], %k[lo]\n\t" MULX_ADD_ROW4(m, a0) "adoxq %[a0], %[a5]"
        : [a0] "+r"(a0), [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "+r"(a4), [a5] "+r"(a5),
        [lo] "=&r"(lo), [hi] "=&r"(hi)
        : [m] "r"(&m), "d"(q), "m"(m)
        : "cc");
}

/// Adds x[]⋅yi to the sparse accumulator a0..a3, the top word goes to a4.
[[gnu::always_inline]] inline void product_row_sparse(uint64_t& a0, uint64_t& a1, uint64_t& a2,
    uint64_t& a3, uint64_t& a4, const Words<>& x, uint64_t yi) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("xorl %k[a4], %k[a4]\n\t" MULX_ADD_ROW4(x, a4)
        : [a0] "+r"(a0), [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "=&r"(a4),
        [lo] "=&r"(lo), [hi] "=&r"(hi)
        : [x] "r"(&x), "d"(yi), "m"(x)
        : "cc");
}

/// Adds q⋅m[] to the sparse accumulator a0..a4, a0 becomes 0.
[[gnu::always_inline]] inline void reduce_row_sparse(uint64_t& a0, uint64_t& a1, uint64_t& a2,
    uint64_t& a3, uint64_t& a4, const Words<>& m, uint64_t q) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("xorl %k[lo], %k[lo]\n\t" MULX_ADD_ROW4(m, a0)
        : [a0] "+r"(a0), [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "+r"(a4), [lo] "=&r"(lo),
        [hi] "=&r"(hi)
        : [m] "r"(&m), "d"(q), "m"(m)
        : "cc");
}

/// Adds q⋅m[] to the accumulator a0..a5 for the pseudo-Mersenne m = 2²⁵⁶ - c, c < 2⁶⁴.
/// Then q⋅m = q⋅2²⁵⁶ - q⋅c and the low word of q⋅c is a0, so a0 is not updated.
[[gnu::always_inline]] inline void reduce_row_pm(uint64_t& a1, uint64_t& a2, uint64_t& a3,
    uint64_t& a4, uint64_t& a5, uint64_t c, uint64_t q) noexcept
{
    uint64_t h = 0;
    asm("mulxq %[c], %[h], %[h]\n\t"  // The high word of q⋅c.
        "addq %%rdx, %[a4]\n\t"
        "adcq $0, %[a5]\n\t"
        "subq %[h], %[a1]\n\t"
        "sbbq $0, %[a2]\n\t"
        "sbbq $0, %[a3]\n\t"
        "sbbq $0, %[a4]\n\t"
        "sbbq $0, %[a5]"
        : [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "+r"(a4), [a5] "+r"(a5), [h] "=&r"(h)
        : [c] "r"(c), "d"(q)
        : "cc");
}

/// Adds q⋅m[] to the accumulator a0..a5 for the P-256 field prime m and q = a0.
/// Then q⋅m = -q + q⋅2⁹⁶ + q⋅m[3]⋅2¹⁹² and -q cancels a0, so a0 is not updated.
[[gnu::always_inline]] inline void reduce_row_p256(
    uint64_t& a1, uint64_t& a2, uint64_t& a3, uint64_t& a4, uint64_t& a5, uint64_t q) noexcept
{
    static constexpr uint64_t K1 = uint64_t{1} << 32;
    static constexpr uint64_t K3 = P256_FIELD_PRIME[3];
    uint64_t lo = 0;
    uint64_t hi = 0;
    // MULX does not change the flags: the second product is computed in the carry chain.
    asm("mulxq %[k1], %[lo], %[hi]\n\t"
        "addq %[lo], %[a1]\n\t"
        "adcq %[hi], %[a2]\n\t"
        "mulxq %[k3], %[lo], %[hi]\n\t"
        "adcq %[lo], %[a3]\n\t"
        "adcq %[hi], %[a4]\n\t"
        "adcq $0, %[a5]"
        : [a1] "+r"(a1), [a2] "+r"(a2), [a3] "+r"(a3), [a4] "+r"(a4), [a5] "+r"(a5), [lo] "=&r"(lo),
        [hi] "=&r"(hi)
        : [k1] "m"(K1), [k3] "m"(K3), "d"(q)
        : "cc");
}

/// Subtracts m from r0..r3 unless it borrows (also from the carry word c if present).
/// The borrow means r is below m.
#define SUB_UNLESS_BORROW(carry_word_sub)     \
    "movq %[r0], %[d0]\n\t"                   \
    "subq (%[m]), %[d0]\n\t"                  \
    "movq %[r1], %[d1]\n\t"                   \
    "sbbq 8(%[m]), %[d1]\n\t"                 \
    "movq %[r2], %[d2]\n\t"                   \
    "sbbq 16(%[m]), %[d2]\n\t"                \
    "movq %[r3], %[d3]\n\t"                   \
    "sbbq 24(%[m]), %[d3]\n\t" carry_word_sub \
    "cmovncq %[d0], %[r0]\n\t"                \
    "cmovncq %[d1], %[r1]\n\t"                \
    "cmovncq %[d2], %[r2]\n\t"                \
    "cmovncq %[d3], %[r3]"

/// Reduces r0..r3 with the carry word c to below m. Requires r < 2m.
[[gnu::always_inline]] inline void final_sub(
    uint64_t& r0, uint64_t& r1, uint64_t& r2, uint64_t& r3, uint64_t c, const Words<>& m) noexcept
{
    uint64_t d0 = 0;
    uint64_t d1 = 0;
    uint64_t d2 = 0;
    uint64_t d3 = 0;
    asm(SUB_UNLESS_BORROW("sbbq $0, %[c]\n\t")
        : [r0] "+r"(r0), [r1] "+r"(r1), [r2] "+r"(r2), [r3] "+r"(r3), [c] "+r"(c), [d0] "=&r"(d0),
        [d1] "=&r"(d1), [d2] "=&r"(d2), [d3] "=&r"(d3)
        : [m] "r"(&m), "m"(m)
        : "cc");
}

/// Reduces r0..r3 to below m. Requires r < 2m.
[[gnu::always_inline]] inline void final_sub(
    uint64_t& r0, uint64_t& r1, uint64_t& r2, uint64_t& r3, const Words<>& m) noexcept
{
    uint64_t d0 = 0;
    uint64_t d1 = 0;
    uint64_t d2 = 0;
    uint64_t d3 = 0;
    asm(SUB_UNLESS_BORROW("")
        : [r0] "+r"(r0), [r1] "+r"(r1), [r2] "+r"(r2), [r3] "+r"(r3), [d0] "=&r"(d0),
        [d1] "=&r"(d1), [d2] "=&r"(d2), [d3] "=&r"(d3)
        : [m] "r"(&m), "m"(m)
        : "cc");
}

// NOLINTEND(hicpp-no-assembler,misc-const-correctness)
#undef SUB_UNLESS_BORROW
#undef MULX_ADD_ROW4
#undef MULX_ADD_LAST
#undef MULX_ADD

/// The CIOS rows: returns the result below 2m (or below R + m) in r0..r3 and the carry word c.
/// The reduce(a0, a1, a2, a3, a4, a5) adds q⋅m[] for q = a0⋅m_inv to the accumulator.
template <typename ReduceFn>
[[gnu::always_inline]] inline void mont_rows(uint64_t& r0, uint64_t& r1, uint64_t& r2, uint64_t& r3,
    uint64_t& c, const Words<>& x, const uint64_t* y, ReduceFn reduce) noexcept
{
    // The rows rotate the accumulator: the word dropped by a reduction becomes the next carry word.
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;
    uint64_t t5 = 0;
    first_row(t0, t1, t2, t3, t4, x, y[0]);
    reduce(t0, t1, t2, t3, t4, t5);
    product_row(t1, t2, t3, t4, t5, t0, x, y[1]);
    reduce(t1, t2, t3, t4, t5, t0);
    product_row(t2, t3, t4, t5, t0, t1, x, y[2]);
    reduce(t2, t3, t4, t5, t0, t1);
    product_row(t3, t4, t5, t0, t1, t2, x, y[3]);
    reduce(t3, t4, t5, t0, t1, t2);
    r0 = t4;
    r1 = t5;
    r2 = t0;
    r3 = t1;
    c = t2;
}

/// The generic reduction for mont_rows().
[[gnu::always_inline]] inline auto generic_reduce(const Words<>& m, uint64_t m_inv) noexcept
{
    assert(m[0] * m_inv == ~uint64_t{0});
    return [&m, m_inv](uint64_t& a0, uint64_t& a1, uint64_t& a2, uint64_t& a3, uint64_t& a4,
               uint64_t& a5) noexcept { reduce_row(a0, a1, a2, a3, a4, a5, m, a0 * m_inv); };
}

EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_adx(
    const intx::uint256& x, const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept
{
    uint64_t r0 = 0;
    uint64_t r1 = 0;
    uint64_t r2 = 0;
    uint64_t r3 = 0;
    uint64_t c = 0;
    mont_rows(r0, r1, r2, r3, c, words(&x[0]), &y[0], generic_reduce(words(&m[0]), m_inv));
    final_sub(r0, r1, r2, r3, c, words(&m[0]));
    return {r0, r1, r2, r3};
}

EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_pm_adx(
    const intx::uint256& x, const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept
{
    assert(m[0] * m_inv == ~uint64_t{0});
    assert((m[1] & m[2] & m[3]) == ~uint64_t{0});
    const auto c = -m[0];  // m = 2²⁵⁶ - c.

    uint64_t r0 = 0;
    uint64_t r1 = 0;
    uint64_t r2 = 0;
    uint64_t r3 = 0;
    uint64_t cw = 0;
    mont_rows(r0, r1, r2, r3, cw, words(&x[0]), &y[0],
        [c, m_inv](uint64_t& a0, uint64_t& a1, uint64_t& a2, uint64_t& a3, uint64_t& a4,
            uint64_t& a5) noexcept { reduce_row_pm(a1, a2, a3, a4, a5, c, a0 * m_inv); });
    final_sub(r0, r1, r2, r3, cw, words(&m[0]));
    return {r0, r1, r2, r3};
}

EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_p256_adx(
    const intx::uint256& x, const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept
{
    assert(m == P256_FIELD_PRIME);
    assert(m_inv == 1);
    (void)m;
    (void)m_inv;

    uint64_t r0 = 0;
    uint64_t r1 = 0;
    uint64_t r2 = 0;
    uint64_t r3 = 0;
    uint64_t cw = 0;
    mont_rows(r0, r1, r2, r3, cw, words(&x[0]), &y[0],
        [](uint64_t& a0, uint64_t& a1, uint64_t& a2, uint64_t& a3, uint64_t& a4,
            uint64_t& a5) noexcept { reduce_row_p256(a1, a2, a3, a4, a5, a0); });
    final_sub(r0, r1, r2, r3, cw, words(&P256_FIELD_PRIME[0]));
    return {r0, r1, r2, r3};
}

EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_sparse_adx(
    const intx::uint256& x, const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept
{
    assert(m[0] * m_inv == ~uint64_t{0});
    assert(m[3] < (uint64_t{1} << 63));
    const auto& xw = words(&x[0]);
    const auto& mw = words(&m[0]);

    // The rows rotate the accumulator: the word dropped by a reduction becomes the next top word.
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;
    first_row(t0, t1, t2, t3, t4, xw, y[0]);
    reduce_row_sparse(t0, t1, t2, t3, t4, mw, t0 * m_inv);
    product_row_sparse(t1, t2, t3, t4, t0, xw, y[1]);
    reduce_row_sparse(t1, t2, t3, t4, t0, mw, t1 * m_inv);
    product_row_sparse(t2, t3, t4, t0, t1, xw, y[2]);
    reduce_row_sparse(t2, t3, t4, t0, t1, mw, t2 * m_inv);
    product_row_sparse(t3, t4, t0, t1, t2, xw, y[3]);
    reduce_row_sparse(t3, t4, t0, t1, t2, mw, t3 * m_inv);

    final_sub(t4, t0, t1, t2, mw);
    return {t4, t0, t1, t2};
}

}  // namespace


EVMONE_PRESERVE_NONE intx::uint256 mul_mont_256_generic(
    const intx::uint256& x, const intx::uint256& y, const intx::uint256& m, uint64_t m_inv) noexcept
{
    return mul_mont_generic(x, y, m, m_inv);
}

#if defined(__BMI2__) && defined(__ADX__)
constinit decltype(&mul_mont_256_generic) mul_mont_256 = mul_mont_256_adx;
constinit decltype(&mul_mont_256_generic) mul_mont_256_sparse = mul_mont_256_sparse_adx;
constinit decltype(&mul_mont_256_generic) mul_mont_256_pm = mul_mont_256_pm_adx;
constinit decltype(&mul_mont_256_generic) mul_mont_256_p256 = mul_mont_256_p256_adx;
#else
extern const bool cpu_has_adx = []() noexcept {
    __builtin_cpu_init();
    return __builtin_cpu_supports("bmi2") && __builtin_cpu_supports("adx");
}();

constinit decltype(&mul_mont_256_generic) mul_mont_256 = mul_mont_256_generic;
constinit decltype(&mul_mont_256_generic) mul_mont_256_sparse = mul_mont_256_generic;
constinit decltype(&mul_mont_256_generic) mul_mont_256_pm = mul_mont_256_generic;
constinit decltype(&mul_mont_256_generic) mul_mont_256_p256 = mul_mont_256_generic;

namespace
{
/// Selects the BMI2 and ADX kernels if the CPU has them.
[[maybe_unused]] const bool adx_kernels_selected = []() noexcept {
    if (!cpu_has_adx)
        return false;
    mul_mont_256 = mul_mont_256_adx;
    mul_mont_256_sparse = mul_mont_256_sparse_adx;
    mul_mont_256_pm = mul_mont_256_pm_adx;
    mul_mont_256_p256 = mul_mont_256_p256_adx;
    return true;
}();
}  // namespace
#endif
}  // namespace evmone::crypto

#endif
