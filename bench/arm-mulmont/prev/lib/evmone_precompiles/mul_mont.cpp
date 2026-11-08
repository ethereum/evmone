// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2026 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "modarith.hpp"
#include "mulmod.hpp"
#include <array>
#include <utility>

#if defined(__x86_64__) || defined(__aarch64__)

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
#ifdef __x86_64__
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

/// Adds src[0..W-1]⋅rdx to the accumulator a0..aW, leaving the OF carry pending to the next word.
/// The zero register z keeps zero and CF = OF = 0 on entry.
#define MULX_ADD_ROW1(src, z) MULX_ADD_LAST(0, src, a0, a1, z)
#define MULX_ADD_ROW2(src, z) MULX_ADD(0, src, a0, a1) MULX_ADD_LAST(8, src, a1, a2, z)
#define MULX_ADD_ROW3(src, z) \
    MULX_ADD(0, src, a0, a1) MULX_ADD(8, src, a1, a2) MULX_ADD_LAST(16, src, a2, a3, z)
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
#endif

// The almost Montgomery multiplication for any number of words n, for modexp: CIOS with the rows
// in blocks of R ≤ 4 words of y. A block goes over x and m in chunks of W ≤ 4 words: a chunk adds
// the products of all the block's rows to a window of registers, stores the words that are done
// and passes the others as the carry into the next chunk. The lowest chunk computes the block's
// factors q. The first block takes n mod 4 rows and the last chunk n mod 4 words (4 instead of 0).
// The accumulator is r[] and its top word, at most 1. For n ≤ 4 the whole multiplication is a
// single chunk of a single block, all in registers.

#ifdef __x86_64__
// NOLINTBEGIN(hicpp-no-assembler,misc-const-correctness)
// clang-format off
#define SET_ROW1 "mulxq (%[s]), %[a0], %[a1]"
#define SET_ROW2 SET_ROW1 "\n\t"                                                      \
    "mulxq 8(%[s]), %[lo], %[a2]\n\t" "addq %[lo], %[a1]\n\t" "adcq $0, %[a2]"
#define SET_ROW3 SET_ROW1 "\n\t"                                                      \
    "mulxq 8(%[s]), %[lo], %[a2]\n\t" "addq %[lo], %[a1]\n\t"                       \
    "mulxq 16(%[s]), %[lo], %[a3]\n\t" "adcq %[lo], %[a2]\n\t" "adcq $0, %[a3]"
#define SET_ROW4 SET_ROW1 "\n\t"                                                      \
    "mulxq 8(%[s]), %[lo], %[a2]\n\t" "addq %[lo], %[a1]\n\t"                       \
    "mulxq 16(%[s]), %[lo], %[a3]\n\t" "adcq %[lo], %[a2]\n\t"                      \
    "mulxq 24(%[s]), %[lo], %[a4]\n\t" "adcq %[lo], %[a3]\n\t" "adcq $0, %[a4]"

#define ROW_OPERANDS1(c) [a0] c(a[P]), [a1] c(a[P + 1])
#define ROW_OPERANDS2(c) ROW_OPERANDS1(c), [a2] c(a[P + 2])
#define ROW_OPERANDS3(c) ROW_OPERANDS2(c), [a3] c(a[P + 3])
#define ROW_OPERANDS4(c) ROW_OPERANDS3(c), [a4] c(a[P + 4])

#define ADD_T1(top) "addq %[t0], %[a0]\n\t" "adcq " top ", %[a1]\n\t" "adcq $0, %[a2]\n\t" "adcq $0, %[a3]\n\t" "adcq $0, %[a4]"
#define ADD_T2(top) "addq %[t0], %[a0]\n\t" "adcq %[t1], %[a1]\n\t" "adcq " top ", %[a2]\n\t" "adcq $0, %[a3]\n\t" "adcq $0, %[a4]"
#define ADD_T3(top) "addq %[t0], %[a0]\n\t" "adcq %[t1], %[a1]\n\t" "adcq %[t2], %[a2]\n\t" "adcq " top ", %[a3]\n\t" "adcq $0, %[a4]"
#define ADD_T4(top) "addq %[t0], %[a0]\n\t" "adcq %[t1], %[a1]\n\t" "adcq %[t2], %[a2]\n\t" "adcq %[t3], %[a3]\n\t" "adcq " top ", %[a4]"
#define T_OPERANDS1 [t0] "m"(t[0])
#define T_OPERANDS2 T_OPERANDS1, [t1] "m"(t[1])
#define T_OPERANDS3 T_OPERANDS2, [t2] "m"(t[2])
#define T_OPERANDS4 T_OPERANDS3, [t3] "m"(t[3])
// clang-format on

/// The rows of W-word chunks s[] times the multiplier y in RDX, on the words a[P..P+W+1] of a
/// window.
template <size_t W>
struct Row;

#define DEFINE_ROW(W)                                                                              \
    template <>                                                                                    \
    struct Row<W>                                                                                  \
    {                                                                                              \
        /** Sets a[P..P+W] = s[]⋅y. */                                                             \
        template <size_t P, size_t K>                                                              \
        [[gnu::always_inline]] static void set(                                                    \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                    \
        {                                                                                          \
            [[maybe_unused]] uint64_t lo = 0;                                                      \
            asm(SET_ROW##W                                                                         \
                : ROW_OPERANDS##W("=&r"), [lo] "=&r"(lo)                                           \
                : [s] "r"(s), "d"(y), "m"(words<W>(s))                                             \
                : "cc");                                                                           \
        }                                                                                          \
        /** Adds s[]⋅y to a[P..P+W], the carry goes to a[P+W+1]. */                                \
        template <size_t P, size_t K>                                                              \
        [[gnu::always_inline]] static void add_new(                                                \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                    \
        {                                                                                          \
            uint64_t lo = 0;                                                                       \
            uint64_t hi = 0;                                                                       \
            asm("xorl %k[top], %k[top]\n\t" MULX_ADD_ROW##W(s, top) "adoxq %[top], %[top]"         \
                : ROW_OPERANDS##W("+r"), [top] "=&r"(a[P + W + 1]), [lo] "=&r"(lo), [hi] "=&r"(hi) \
                : [s] "r"(s), "d"(y), "m"(words<W>(s))                                             \
                : "cc");                                                                           \
        }                                                                                          \
        /** Adds s[]⋅y to a[P..P+W+1] where y makes a[P] 0. */                                     \
        template <size_t P, size_t K>                                                              \
        [[gnu::always_inline]] static void add_cancel(                                             \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                    \
        {                                                                                          \
            uint64_t lo = 0;                                                                       \
            uint64_t hi = 0;                                                                       \
            asm("xorl %k[lo], %k[lo]\n\t" MULX_ADD_ROW##W(s, a0) "adoxq %[a0], %[top]"             \
                : ROW_OPERANDS##W("+r"), [top] "+r"(a[P + W + 1]), [lo] "=&r"(lo), [hi] "=&r"(hi)  \
                : [s] "r"(s), "d"(y), "m"(words<W>(s))                                             \
                : "cc");                                                                           \
        }                                                                                          \
        /** Adds s[]⋅y to a[P..P+W+1]. */                                                          \
        template <size_t P, size_t K>                                                              \
        [[gnu::always_inline]] static void add(                                                    \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                    \
        {                                                                                          \
            uint64_t lo = 0;                                                                       \
            uint64_t hi = 0;                                                                       \
            asm("xorl %k[lo], %k[lo]\n\t" MULX_ADD_ROW##W(s, z) "adoxq %[z], %[top]"               \
                : ROW_OPERANDS##W("+r"), [top] "+r"(a[P + W + 1]), [lo] "=&r"(lo), [hi] "=&r"(hi)  \
                : [s] "r"(s), "d"(y), [z] "r"(uint64_t{0}), "m"(words<W>(s))                       \
                : "cc");                                                                           \
        }                                                                                          \
        /** Adds t[0..W-1] to a[0..4]. */                                                          \
        template <size_t K>                                                                        \
        [[gnu::always_inline]] static void add_t(                                                  \
            std::array<uint64_t, K>& a, const uint64_t* t) noexcept                                \
        {                                                                                          \
            static constexpr size_t P = 0;                                                         \
            asm(ADD_T##W("$0") : ROW_OPERANDS4("+r") : T_OPERANDS##W : "cc");                      \
        }                                                                                          \
        /** Adds t[0..W-1] and top⋅2^(64W) to a[0..4]. */                                          \
        template <size_t K>                                                                        \
        [[gnu::always_inline]] static void add_t_top(                                              \
            std::array<uint64_t, K>& a, const uint64_t* t, uint64_t top) noexcept                  \
        {                                                                                          \
            static constexpr size_t P = 0;                                                         \
            asm(ADD_T##W("%[top]") : ROW_OPERANDS4("+r") : T_OPERANDS##W, [top] "r"(top) : "cc");  \
        }                                                                                          \
    };

DEFINE_ROW(1)
DEFINE_ROW(2)
DEFINE_ROW(3)
DEFINE_ROW(4)

/// Adds h[] to a[W+1..4] for W < 4 and propagates the carry up to a[W+4].
template <size_t W, size_t K, size_t H>
[[gnu::always_inline]] inline void add_high(
    std::array<uint64_t, K>& a, const std::array<uint64_t, H>& h) noexcept
{
    static constexpr size_t P = W + 1;
    if constexpr (W == 1)
    {
        asm("addq %[h0], %[a0]\n\tadcq %[h1], %[a1]\n\tadcq %[h2], %[a2]\n\tadcq $0, %[a3]"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0]), [h1] "r"(h[1]), [h2] "r"(h[2])
            : "cc");
    }
    else if constexpr (W == 2)
    {
        asm("addq %[h0], %[a0]\n\tadcq %[h1], %[a1]\n\tadcq $0, %[a2]\n\tadcq $0, %[a3]"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0]), [h1] "r"(h[1])
            : "cc");
    }
    else
    {
        asm("addq %[h0], %[a0]\n\tadcq $0, %[a1]\n\tadcq $0, %[a2]\n\tadcq $0, %[a3]"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0])
            : "cc");
    }
}

// NOLINTEND(hicpp-no-assembler,misc-const-correctness)
#undef DEFINE_ROW
#undef T_OPERANDS4
#undef T_OPERANDS3
#undef T_OPERANDS2
#undef T_OPERANDS1
#undef ADD_T4
#undef ADD_T3
#undef ADD_T2
#undef ADD_T1
#undef ROW_OPERANDS4
#undef ROW_OPERANDS3
#undef ROW_OPERANDS2
#undef ROW_OPERANDS1
#undef SET_ROW4
#undef SET_ROW3
#undef SET_ROW2
#undef SET_ROW1
#undef MULX_ADD_ROW4
#undef MULX_ADD_ROW3
#undef MULX_ADD_ROW2
#undef MULX_ADD_ROW1
#undef MULX_ADD_LAST
#undef MULX_ADD
#else
// The aarch64 rows compute the low halves of the products, add them in a carry chain, then compute
// the high halves into the same registers and add them in another chain one word up.

// NOLINTBEGIN(hicpp-no-assembler,misc-const-correctness)
// clang-format off
#define LO(i) "mul %[t" #i "], %[s" #i "], %[y]\n\t"
#define HI(i) "umulh %[t" #i "], %[s" #i "], %[y]\n\t"
#define LOS1 LO(0)
#define LOS2 LOS1 LO(1)
#define LOS3 LOS2 LO(2)
#define LOS4 LOS3 LO(3)
// Without the low half of s[0]⋅y, which cancels a[0].
#define LOSC1
#define LOSC2 LO(1)
#define LOSC3 LO(1) LO(2)
#define LOSC4 LO(1) LO(2) LO(3)
#define HIS1 HI(0)
#define HIS2 HIS1 HI(1)
#define HIS3 HIS2 HI(2)
#define HIS4 HIS3 HI(3)

#define ADD_LO0 "adds %[a0], %[a0], %[t0]\n\t"
// The carry of a[0] + lo(s[0]⋅y) = 0 (mod 2⁶⁴) is a[0] ≠ 0.
#define CANCEL_LO0 "subs xzr, %[a0], #1\n\t"
// The low halves; MUL and UMULH keep the flags, so the carry waits for the high half of the last
// product, which cannot overflow.
#define LO_PASS1(op0) op0
#define LO_PASS2(op0) op0 "adcs %[a1], %[a1], %[t1]\n\t"
#define LO_PASS3(op0) op0 "adcs %[a1], %[a1], %[t1]\n\t" "adcs %[a2], %[a2], %[t2]\n\t"
#define LO_PASS4(op0) op0 "adcs %[a1], %[a1], %[t1]\n\t" "adcs %[a2], %[a2], %[t2]\n\t" \
    "adcs %[a3], %[a3], %[t3]\n\t"
#define ABSORB(i) "adc %[t" #i "], %[t" #i "], xzr\n\t"
// The high halves, one word up; the carry goes to the top word.
#define HI_PASS1 ABSORB(0) "adds %[a1], %[a1], %[t0]\n\t"
#define HI_PASS2 ABSORB(1) "adds %[a1], %[a1], %[t0]\n\t" "adcs %[a2], %[a2], %[t1]\n\t"
#define HI_PASS3 ABSORB(2) "adds %[a1], %[a1], %[t0]\n\t" "adcs %[a2], %[a2], %[t1]\n\t" \
    "adcs %[a3], %[a3], %[t2]\n\t"
#define HI_PASS4 ABSORB(3) "adds %[a1], %[a1], %[t0]\n\t" "adcs %[a2], %[a2], %[t1]\n\t" \
    "adcs %[a3], %[a3], %[t2]\n\t" "adcs %[a4], %[a4], %[t3]\n\t"
#define TOP_NEW "adc %[top], xzr, xzr"
#define TOP_ADD "adc %[top], %[top], xzr"

#define SET1 "mul %[a0], %[s0], %[y]\n\t" "umulh %[a1], %[s0], %[y]"
#define SET2 "mul %[a0], %[s0], %[y]\n\t" "umulh %[t0], %[s0], %[y]\n\t" LO(1) HI2(1) \
    "adds %[a1], %[t1], %[t0]\n\t" "adc %[a2], %[u1], xzr"
#define SET3 "mul %[a0], %[s0], %[y]\n\t" "umulh %[t0], %[s0], %[y]\n\t" LO(1) HI2(1) LO(2) HI2(2) \
    "adds %[a1], %[t1], %[t0]\n\t" "adcs %[a2], %[t2], %[u1]\n\t" "adc %[a3], %[u2], xzr"
#define SET4 "mul %[a0], %[s0], %[y]\n\t" "umulh %[t0], %[s0], %[y]\n\t" LO(1) HI2(1) LO(2) HI2(2) \
    LO(3) HI2(3) "adds %[a1], %[t1], %[t0]\n\t" "adcs %[a2], %[t2], %[u1]\n\t" \
    "adcs %[a3], %[t3], %[u2]\n\t" "adc %[a4], %[u3], xzr"
#define HI2(i) "umulh %[u" #i "], %[s" #i "], %[y]\n\t"

#define ROW_OPERANDS1(c) [a0] c(a[P]), [a1] c(a[P + 1])
#define ROW_OPERANDS2(c) ROW_OPERANDS1(c), [a2] c(a[P + 2])
#define ROW_OPERANDS3(c) ROW_OPERANDS2(c), [a3] c(a[P + 3])
#define ROW_OPERANDS4(c) ROW_OPERANDS3(c), [a4] c(a[P + 4])
#define S_OPERANDS1 [s0] "r"(s[0])
#define S_OPERANDS2 S_OPERANDS1, [s1] "r"(s[1])
#define S_OPERANDS3 S_OPERANDS2, [s2] "r"(s[2])
#define S_OPERANDS4 S_OPERANDS3, [s3] "r"(s[3])
#define TMP_OPERANDS1 [t0] "=&r"(t[0])
#define TMP_OPERANDS2 TMP_OPERANDS1, [t1] "=&r"(t[1])
#define TMP_OPERANDS3 TMP_OPERANDS2, [t2] "=&r"(t[2])
#define TMP_OPERANDS4 TMP_OPERANDS3, [t3] "=&r"(t[3])
#define SET_TMP_OPERANDS1 [t0] "=&r"(t[0])
#define SET_TMP_OPERANDS2 SET_TMP_OPERANDS1, [t1] "=&r"(t[1]), [u1] "=&r"(h[1])
#define SET_TMP_OPERANDS3 SET_TMP_OPERANDS2, [t2] "=&r"(t[2]), [u2] "=&r"(h[2])
#define SET_TMP_OPERANDS4 SET_TMP_OPERANDS3, [t3] "=&r"(t[3]), [u3] "=&r"(h[3])

#define ADD_T1(top) "adds %[a0], %[a0], %[u0]\n\t" "adcs %[a1], %[a1], " top "\n\t" \
    "adcs %[a2], %[a2], xzr\n\t" "adcs %[a3], %[a3], xzr\n\t" "adc %[a4], %[a4], xzr"
#define ADD_T2(top) "adds %[a0], %[a0], %[u0]\n\t" "adcs %[a1], %[a1], %[u1]\n\t" \
    "adcs %[a2], %[a2], " top "\n\t" "adcs %[a3], %[a3], xzr\n\t" "adc %[a4], %[a4], xzr"
#define ADD_T3(top) "adds %[a0], %[a0], %[u0]\n\t" "adcs %[a1], %[a1], %[u1]\n\t" \
    "adcs %[a2], %[a2], %[u2]\n\t" "adcs %[a3], %[a3], " top "\n\t" "adc %[a4], %[a4], xzr"
#define ADD_T4(top) "adds %[a0], %[a0], %[u0]\n\t" "adcs %[a1], %[a1], %[u1]\n\t" \
    "adcs %[a2], %[a2], %[u2]\n\t" "adcs %[a3], %[a3], %[u3]\n\t" "adc %[a4], %[a4], " top
#define T_OPERANDS1 [u0] "r"(t[0])
#define T_OPERANDS2 T_OPERANDS1, [u1] "r"(t[1])
#define T_OPERANDS3 T_OPERANDS2, [u2] "r"(t[2])
#define T_OPERANDS4 T_OPERANDS3, [u3] "r"(t[3])
// clang-format on

template <size_t W>
struct Row;

#define DEFINE_ROW(W)                                                                             \
    template <>                                                                                   \
    struct Row<W>                                                                                 \
    {                                                                                             \
        template <size_t P, size_t K>                                                             \
        [[gnu::always_inline]] static void set(                                                   \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                   \
        {                                                                                         \
            [[maybe_unused]] std::array<uint64_t, W> t;                                           \
            [[maybe_unused]] std::array<uint64_t, W> h;                                           \
            asm(SET##W                                                                            \
                : ROW_OPERANDS##W("=&r"), SET_TMP_OPERANDS##W                                     \
                : S_OPERANDS##W, [y] "r"(y)                                                       \
                : "cc");                                                                          \
        }                                                                                         \
        template <size_t P, size_t K>                                                             \
        [[gnu::always_inline]] static void add_new(                                               \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                   \
        {                                                                                         \
            std::array<uint64_t, W> t;                                                            \
            asm(LOS##W LO_PASS##W(ADD_LO0) HIS##W HI_PASS##W TOP_NEW                              \
                : ROW_OPERANDS##W("+r"), [top] "=&r"(a[P + W + 1]), TMP_OPERANDS##W               \
                : S_OPERANDS##W, [y] "r"(y)                                                       \
                : "cc");                                                                          \
        }                                                                                         \
        template <size_t P, size_t K>                                                             \
        [[gnu::always_inline]] static void add_cancel(                                            \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                   \
        {                                                                                         \
            std::array<uint64_t, W> t;                                                            \
            asm(LOSC##W LO_PASS##W(CANCEL_LO0) HIS##W HI_PASS##W TOP_ADD                          \
                : ROW_OPERANDS##W("+r"), [top] "+r"(a[P + W + 1]), TMP_OPERANDS##W                \
                : S_OPERANDS##W, [y] "r"(y)                                                       \
                : "cc");                                                                          \
        }                                                                                         \
        template <size_t P, size_t K>                                                             \
        [[gnu::always_inline]] static void add(                                                   \
            std::array<uint64_t, K>& a, const uint64_t* s, uint64_t y) noexcept                   \
        {                                                                                         \
            std::array<uint64_t, W> t;                                                            \
            asm(LOS##W LO_PASS##W(ADD_LO0) HIS##W HI_PASS##W TOP_ADD                              \
                : ROW_OPERANDS##W("+r"), [top] "+r"(a[P + W + 1]), TMP_OPERANDS##W                \
                : S_OPERANDS##W, [y] "r"(y)                                                       \
                : "cc");                                                                          \
        }                                                                                         \
        template <size_t K>                                                                       \
        [[gnu::always_inline]] static void add_t(                                                 \
            std::array<uint64_t, K>& a, const uint64_t* t) noexcept                               \
        {                                                                                         \
            static constexpr size_t P = 0;                                                        \
            asm(ADD_T##W("xzr") : ROW_OPERANDS4("+r") : T_OPERANDS##W : "cc");                    \
        }                                                                                         \
        template <size_t K>                                                                       \
        [[gnu::always_inline]] static void add_t_top(                                             \
            std::array<uint64_t, K>& a, const uint64_t* t, uint64_t top) noexcept                 \
        {                                                                                         \
            static constexpr size_t P = 0;                                                        \
            asm(ADD_T##W("%[top]") : ROW_OPERANDS4("+r") : T_OPERANDS##W, [top] "r"(top) : "cc"); \
        }                                                                                         \
    };

DEFINE_ROW(1)
DEFINE_ROW(2)
DEFINE_ROW(3)
DEFINE_ROW(4)

template <size_t W, size_t K, size_t H>
[[gnu::always_inline]] inline void add_high(
    std::array<uint64_t, K>& a, const std::array<uint64_t, H>& h) noexcept
{
    static constexpr size_t P = W + 1;
    if constexpr (W == 1)
    {
        asm("adds %[a0], %[a0], %[h0]\n\tadcs %[a1], %[a1], %[h1]\n\t"
            "adcs %[a2], %[a2], %[h2]\n\tadc %[a3], %[a3], xzr"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0]), [h1] "r"(h[1]), [h2] "r"(h[2])
            : "cc");
    }
    else if constexpr (W == 2)
    {
        asm("adds %[a0], %[a0], %[h0]\n\tadcs %[a1], %[a1], %[h1]\n\t"
            "adcs %[a2], %[a2], xzr\n\tadc %[a3], %[a3], xzr"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0]), [h1] "r"(h[1])
            : "cc");
    }
    else
    {
        asm("adds %[a0], %[a0], %[h0]\n\tadcs %[a1], %[a1], xzr\n\t"
            "adcs %[a2], %[a2], xzr\n\tadc %[a3], %[a3], xzr"
            : ROW_OPERANDS3("+r")
            : [h0] "r"(h[0])
            : "cc");
    }
}

// NOLINTEND(hicpp-no-assembler,misc-const-correctness)
#undef DEFINE_ROW
#undef T_OPERANDS4
#undef T_OPERANDS3
#undef T_OPERANDS2
#undef T_OPERANDS1
#undef ADD_T4
#undef ADD_T3
#undef ADD_T2
#undef ADD_T1
#undef SET_TMP_OPERANDS4
#undef SET_TMP_OPERANDS3
#undef SET_TMP_OPERANDS2
#undef SET_TMP_OPERANDS1
#undef TMP_OPERANDS4
#undef TMP_OPERANDS3
#undef TMP_OPERANDS2
#undef TMP_OPERANDS1
#undef S_OPERANDS4
#undef S_OPERANDS3
#undef S_OPERANDS2
#undef S_OPERANDS1
#undef ROW_OPERANDS4
#undef ROW_OPERANDS3
#undef ROW_OPERANDS2
#undef ROW_OPERANDS1
#undef HI2
#undef SET4
#undef SET3
#undef SET2
#undef SET1
#undef TOP_ADD
#undef TOP_NEW
#undef HI_PASS4
#undef HI_PASS3
#undef HI_PASS2
#undef HI_PASS1
#undef ABSORB
#undef LO_PASS4
#undef LO_PASS3
#undef LO_PASS2
#undef LO_PASS1
#undef CANCEL_LO0
#undef ADD_LO0
#undef HIS4
#undef HIS3
#undef HIS2
#undef HIS1
#undef LOSC4
#undef LOSC3
#undef LOSC2
#undef LOSC1
#undef LOS4
#undef LOS3
#undef LOS2
#undef LOS1
#undef HI
#undef LO
#endif

// The copies between the windows and the memory spell out the word indices: a loop over a
// std::array keeps GCC from holding its words in registers.

/// Copies s[S..S+C-1] to d[D..D+C-1].
template <size_t D, size_t S, typename Dst, typename Src, size_t... I>
[[gnu::always_inline]] inline void copy_words(
    Dst& d, const Src& s, std::index_sequence<I...>) noexcept
{
    ((d[D + I] = s[S + I]), ...);
}

template <size_t D, size_t S, size_t C, typename Dst, typename Src>
[[gnu::always_inline]] inline void copy_words(Dst& d, const Src& s) noexcept
{
    copy_words<D, S>(d, s, std::make_index_sequence<C>{});
}

/// Row r of the lowest chunk: computes q[r] and adds q[r]⋅m[], which makes a[r] 0.
/// Without ADD_T the window is still empty at row 0.
template <size_t W, bool ADD_T, size_t r, size_t K, size_t R>
[[gnu::always_inline]] inline void low_chunk_row(std::array<uint64_t, K>& a,
    std::array<uint64_t, R>& q, const uint64_t* x, const uint64_t* y, const uint64_t* m,
    uint64_t m_inv) noexcept
{
    if constexpr (r == 0 && !ADD_T)
    {
        Row<W>::template set<0>(a, x, y[0]);
        a[W + 1] = 0;
    }
    else
        Row<W>::template add_new<r>(a, x, y[r]);
    q[r] = a[r] * m_inv;
    Row<W>::template add_cancel<r>(a, m, q[r]);
}

template <size_t W, bool ADD_T, size_t K, size_t R, size_t... I>
[[gnu::always_inline]] inline void low_chunk_rows(std::array<uint64_t, K>& a,
    std::array<uint64_t, R>& q, const uint64_t* x, const uint64_t* y, const uint64_t* m,
    uint64_t m_inv, std::index_sequence<I...>) noexcept
{
    (low_chunk_row<W, ADD_T, I>(a, q, x, y, m, m_inv), ...);
}

/// The lowest chunk of a block of R rows, of W ≥ R words: computes q[] and the carry c[] into
/// the next chunk. With ADD_T it starts from the accumulator words t[0..W-1], which it shifts by
/// R words.
template <size_t W, size_t R, bool ADD_T>
[[gnu::always_inline]] inline void low_chunk(std::array<uint64_t, R + 1>& c,
    std::array<uint64_t, R>& q, uint64_t* t, const uint64_t* x, const uint64_t* y,
    const uint64_t* m, uint64_t m_inv) noexcept
{
    static_assert(W >= R);
    std::array<uint64_t, W + R + 1> a;  // NOLINT(*-member-init): the rows set the words.
    if constexpr (ADD_T)
    {
        copy_words<0, 0, W>(a, t);
        a[W] = 0;
    }
    low_chunk_rows<W, ADD_T>(a, q, x, y, m, m_inv, std::make_index_sequence<R>{});
    copy_words<0, R, W - R>(t, a);
    copy_words<0, W, R + 1>(c, a);
}

/// Row r of a chunk above the lowest: the word a[r] is then done.
template <size_t W, size_t r, size_t K, size_t R>
[[gnu::always_inline]] inline void chunk_row(std::array<uint64_t, K>& a, uint64_t* out,
    const uint64_t* x, const uint64_t* y, const uint64_t* m,
    const std::array<uint64_t, R>& q) noexcept
{
    Row<W>::template add_new<r>(a, x, y[r]);
    Row<W>::template add<r>(a, m, q[r]);
    if constexpr (r <= W)
        out[r] = a[r];
}

template <size_t W, size_t K, size_t R, size_t... I>
[[gnu::always_inline]] inline void chunk_rows(std::array<uint64_t, K>& a, uint64_t* out,
    const uint64_t* x, const uint64_t* y, const uint64_t* m, const std::array<uint64_t, R>& q,
    std::index_sequence<I...>) noexcept
{
    (chunk_row<W, I>(a, out, x, y, m, q), ...);
}

/// A chunk of W words of a block of R rows, with the carry c[] from the chunk below.
/// With ADD_T it adds the accumulator words t[0..W-1]. It stores the words that are done to out[]
/// and the carry into the next chunk to c[], but the last chunk stores all the words of the
/// accumulator except its top word, which it adds before and replaces after.
template <size_t W, size_t R, bool ADD_T, bool LAST>
[[gnu::always_inline]] inline void chunk(std::array<uint64_t, R + 1>& c, const uint64_t* t,
    uint64_t* out, const uint64_t* x, const uint64_t* y, const uint64_t* m,
    const std::array<uint64_t, R>& q, uint64_t& top) noexcept
{
    std::array<uint64_t, W + R + 1> a;  // NOLINT(*-member-init): the rows set the words.
    copy_words<0, 0, R + 1>(a, c);
    if constexpr (W > R)
        copy_words<R + 1, 0, W - R>(a, std::array<uint64_t, W - R>{});
    if constexpr (ADD_T)
    {
        static_assert(R == 4);
        if constexpr (LAST)
            Row<W>::add_t_top(a, t, top);
        else
            Row<W>::add_t(a, t);
    }

    // For W < R the carry words above the chunk would be the top words of the first rows,
    // which take only a carry. Leave them out and add them after the rows.
    static constexpr bool SPLIT = W < R;
    static_assert(!SPLIT || LAST);
    std::array<uint64_t, SPLIT ? R - W : 1> h{};
    if constexpr (SPLIT)
        copy_words<0, W + 1, R - W>(h, a);

    chunk_rows<W>(a, out, x, y, m, q, std::make_index_sequence<R>{});

    if constexpr (SPLIT)
        add_high<W>(a, h);
    if constexpr (W + 1 < R)
        copy_words<W + 1, W + 1, R - W - 1>(out, a);
    if constexpr (LAST)
    {
        copy_words<R, R, W>(out, a);
        top = a[W + R];
    }
    else
    {
        copy_words<R, R, W - R>(out, a);
        copy_words<0, W, R + 1>(c, a);
    }
}

/// A block of R rows for n = 4⋅k + S words, which shifts the accumulator t[] by R words.
template <size_t R, bool ADD_T, size_t S>
[[gnu::always_inline]] inline void block(uint64_t* t, const uint64_t* x, const uint64_t* y,
    const uint64_t* m, uint64_t m_inv, size_t k, uint64_t& top) noexcept
{
    std::array<uint64_t, R + 1> c;  // NOLINT(*-member-init): set by low_chunk().
    std::array<uint64_t, R> q;      // NOLINT(*-member-init): set by low_chunk().
    low_chunk<4, R, ADD_T>(c, q, t, x, y, m, m_inv);
    static constexpr size_t LAST_W = S == 0 ? 4 : S;
    const auto last = S == 0 ? k - 1 : k;
    for (size_t j = 1; j < last; ++j)
        chunk<4, R, ADD_T, false>(c, t + 4 * j, t + 4 * j - R, x + 4 * j, y, m + 4 * j, q, top);
    chunk<LAST_W, R, ADD_T, true>(
        c, t + 4 * last, t + 4 * last - R, x + 4 * last, y, m + 4 * last, q, top);
}

/// The almost Montgomery multiplication for n = 4⋅k + S > 4 words.
template <size_t S>
[[gnu::noinline]] void mul_amm_blocks(uint64_t* r, const uint64_t* x, const uint64_t* y,
    const uint64_t* m, uint64_t m_inv, size_t n) noexcept
{
    static constexpr size_t FIRST_R = S == 0 ? 4 : S;
    const auto k = n / 4;
    uint64_t top = 0;
    block<FIRST_R, false, S>(r, x, y, m, m_inv, k, top);
    for (size_t i = FIRST_R; i < n; i += 4)
        block<4, true, S>(r, x, y + i, m, m_inv, k, top);
    if (top != 0)
        sub({r, n}, {m, n});
}

/// The almost Montgomery multiplication for N ≤ 4 words.
template <size_t N>
[[gnu::always_inline]] inline void mul_amm_small(
    uint64_t* r, const uint64_t* x, const uint64_t* y, const uint64_t* m, uint64_t m_inv) noexcept
{
    std::array<uint64_t, N + 1> c;  // NOLINT(*-member-init): set by low_chunk().
    std::array<uint64_t, N> q;      // NOLINT(*-member-init): set by low_chunk().
    low_chunk<N, N, false>(c, q, r, x, y, m, m_inv);
    if (c[N] != 0)
    {
        [&]<size_t... I>(std::index_sequence<I...>) {
            bool borrow = false;
            ((std::tie(c[I], borrow) = intx::subc(c[I], m[I], borrow)), ...);
        }(std::make_index_sequence<N>{});
    }
    copy_words<0, 0, N>(r, c);
}

}  // namespace

EVMONE_PRESERVE_NONE void mul_amm_asm(uint64_t* r, const uint64_t* x, const uint64_t* y,
    const uint64_t* mod, uint64_t mod_inv, size_t n) noexcept
{
    assert(mod[0] * mod_inv == ~uint64_t{0});
    assert(mod[n - 1] != 0);
    assert(r != x && r != y);
    if (n == 4) [[likely]]
        return mul_amm_small<4>(r, x, y, mod, mod_inv);
    switch (n)
    {
    case 1:
        return mul_amm_small<1>(r, x, y, mod, mod_inv);
    case 2:
        return mul_amm_small<2>(r, x, y, mod, mod_inv);
    case 3:
        return mul_amm_small<3>(r, x, y, mod, mod_inv);
    default:
        break;
    }
    switch (n % 4)
    {
    case 0:
        return mul_amm_blocks<0>(r, x, y, mod, mod_inv, n);
    case 1:
        return mul_amm_blocks<1>(r, x, y, mod, mod_inv, n);
    case 2:
        return mul_amm_blocks<2>(r, x, y, mod, mod_inv, n);
    default:
        return mul_amm_blocks<3>(r, x, y, mod, mod_inv, n);
    }
}

#ifdef __x86_64__
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
#endif
}  // namespace evmone::crypto

#endif
