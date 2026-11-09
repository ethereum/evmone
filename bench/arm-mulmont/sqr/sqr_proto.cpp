// Prototype: the almost Montgomery squaring for n = 4k > 4 words with separated operand scanning
// (SOS, Koç, Acar, Kaliski 1996): T = x² with the cross products computed once (doubled, plus the
// squares), then the reduction of T's low half by reduction-only CIOS blocks, plus T's high half.
#include MM_SRC

#include <cstring>

namespace evmone::crypto
{
namespace
{
using u64 = uint64_t;

/// The diagonal tile of the triangle block of the rows x[0..3]: x[r]⋅x[r+1..3] on the window
/// T[0..8] (relative). With LAST it is the last chunk of the last block: it adds top to a[4]
/// and stores all the words.
template <bool LAST>
[[gnu::always_inline]] inline void tri_diag(
    std::array<u64, 5>& c, u64* t, const u64* x, u64 top) noexcept
{
    std::array<u64, 9> a;  // NOLINT
    copy_words<0, 0, 4>(a, t);
    a[4] = LAST ? top : 0;
    Row<3>::add_new<1>(a, x + 1, x[0]);
    Row<2>::add_new<3>(a, x + 2, x[1]);
    Row<1>::add_new<5>(a, x + 3, x[2]);
    if constexpr (LAST)
        copy_words<1, 1, 7>(t, a);
    else
    {
        copy_words<1, 1, 3>(t, a);
        copy_words<0, 4, 4>(c, a);
        c[4] = 0;
    }
}

/// A full tile of the triangle block: the rows y[0..3] times x[0..3] on the window at t.
template <bool LAST>
[[gnu::always_inline]] inline void tri_chunk(
    std::array<u64, 5>& c, u64* t, const u64* x, const u64* y, u64& top) noexcept
{
    std::array<u64, 9> a;  // NOLINT
    copy_words<0, 0, 5>(a, c);
    if constexpr (LAST)
        Row<4>::add_t_top(a, t, top);
    else
        Row<4>::add_t(a, t);
    Row<4>::add_new<0>(a, x, y[0]);
    t[0] = a[0];
    Row<4>::add_new<1>(a, x, y[1]);
    t[1] = a[1];
    Row<4>::add_new<2>(a, x, y[2]);
    t[2] = a[2];
    Row<4>::add_new<3>(a, x, y[3]);
    t[3] = a[3];
    if constexpr (LAST)
    {
        copy_words<4, 4, 4>(t, a);
        top = a[8];
    }
    else
        copy_words<0, 4, 5>(c, a);
}

/// T[0..2n-1] = the cross products Σ x[i]⋅x[j] for i < j. Requires T[0..n-1] = 0.
[[gnu::always_inline]] inline void triangle(u64* T, const u64* x, size_t k) noexcept
{
    u64 top = 0;
    std::array<u64, 5> c;  // NOLINT
    for (size_t b = 0; b + 1 < k; ++b)
    {
        tri_diag<false>(c, T + 8 * b, x + 4 * b, 0);
        for (size_t j = b + 1; j + 1 < k; ++j)
            tri_chunk<false>(c, T + 4 * b + 4 * j, x + 4 * j, x + 4 * b, top);
        tri_chunk<true>(c, T + 4 * b + 4 * (k - 1), x + 4 * (k - 1), x + 4 * b, top);
    }
    tri_diag<true>(c, T + 8 * (k - 1), x + 4 * (k - 1), top);
}

#ifdef __x86_64__
/// T = 2⋅T + Σ x[i]²⋅2^(128i): the doubling on CF, the squares on OF, 4 words of x per asm
/// statement with the carries passed in registers.
[[gnu::always_inline]] inline void double_add_squares(u64* T, const u64* x, size_t n) noexcept
{
    u64 c1 = 0;
    u64 c2 = 0;
    for (size_t i = 0; i < n; i += 4, T += 8, x += 4)
    {
        u64 w0, w1, lo, hi;  // NOLINT
        const u64 m1 = ~u64{0};
        // clang-format off
#define DS_STEP(i) \
        "movq " #i "*8(%[x]), %%rdx\n\t" "mulxq %%rdx, %[lo], %[hi]\n\t" \
        "movq " #i "*16(%[t]), %[w0]\n\t" "adcxq %[w0], %[w0]\n\t" "adoxq %[lo], %[w0]\n\t" \
        "movq %[w0], " #i "*16(%[t])\n\t" \
        "movq " #i "*16+8(%[t]), %[w1]\n\t" "adcxq %[w1], %[w1]\n\t" "adoxq %[hi], %[w1]\n\t" \
        "movq %[w1], " #i "*16+8(%[t])\n\t"
        asm volatile(
            "addq %[imax], %[c2]\n\t"
            "adcxq %[m1], %[c1]\n\t"
            DS_STEP(0) DS_STEP(1) DS_STEP(2) DS_STEP(3)
            "movl $0, %k[c1]\n\t"
            "movl $0, %k[c2]\n\t"
            "adcxq %[c1], %[c1]\n\t"
            "adoxq %[c2], %[c2]"
            : [c1] "+&r"(c1), [c2] "+&r"(c2), [w0] "=&r"(w0), [w1] "=&r"(w1), [lo] "=&r"(lo),
              [hi] "=&r"(hi)
            : [t] "r"(T), [x] "r"(x), [m1] "r"(m1), [imax] "r"(u64{0x7fffffffffffffff})
            : "rdx", "cc", "memory");
#undef DS_STEP
        // clang-format on
    }
}

/// r = a + b for n = 4k words, returns the carry.
[[gnu::always_inline]] inline u64 add_n(u64* r, const u64* a, const u64* b, size_t n) noexcept
{
    u64 c = 0;
    for (size_t i = 0; i < n; i += 4)
    {
        u64 w;  // NOLINT
        // clang-format off
#define AD_STEP(i) "movq " #i "*8(%[a]), %[w]\n\t" "adcq " #i "*8(%[b]), %[w]\n\t" "movq %[w], " #i "*8(%[r])\n\t"
        asm volatile(
            "addq $-1, %[c]\n\t"
            AD_STEP(0) AD_STEP(1) AD_STEP(2) AD_STEP(3)
            "movl $0, %k[c]\n\t"
            "adcq $0, %[c]"
            : [c] "+&r"(c), [w] "=&r"(w)
            : [r] "r"(r + i), [a] "r"(a + i), [b] "r"(b + i)
            : "cc", "memory");
#undef AD_STEP
        // clang-format on
    }
    return c;
}

#else
/// T = 2⋅T + Σ x[i]²⋅2^(128i): 4 words of x per asm statement, the doubling chain, then the
/// squares chain, the carries passed in registers.
[[gnu::always_inline]] inline void double_add_squares(u64* T, const u64* x, size_t n) noexcept
{
    u64 c1 = 0;
    u64 c2 = 0;
    for (size_t i = 0; i < n; i += 4, T += 8, x += 4)
    {
        u64 w0, w1, w2, w3, w4, w5, w6, w7, s0, s1, s2, s3, s4, s5, s6, s7;  // NOLINT
        asm volatile(
            "ldp %[w0], %[w1], [%[t]]\n\t"
            "ldp %[w2], %[w3], [%[t], #16]\n\t"
            "ldp %[w4], %[w5], [%[t], #32]\n\t"
            "ldp %[w6], %[w7], [%[t], #48]\n\t"
            "ldp %[s1], %[s3], [%[x]]\n\t"
            "ldp %[s5], %[s7], [%[x], #16]\n\t"
            "mul %[s0], %[s1], %[s1]\n\t"
            "umulh %[s1], %[s1], %[s1]\n\t"
            "mul %[s2], %[s3], %[s3]\n\t"
            "umulh %[s3], %[s3], %[s3]\n\t"
            "mul %[s4], %[s5], %[s5]\n\t"
            "umulh %[s5], %[s5], %[s5]\n\t"
            "mul %[s6], %[s7], %[s7]\n\t"
            "umulh %[s7], %[s7], %[s7]\n\t"
            "subs xzr, %[c1], #1\n\t"
            "adcs %[w0], %[w0], %[w0]\n\t"
            "adcs %[w1], %[w1], %[w1]\n\t"
            "adcs %[w2], %[w2], %[w2]\n\t"
            "adcs %[w3], %[w3], %[w3]\n\t"
            "adcs %[w4], %[w4], %[w4]\n\t"
            "adcs %[w5], %[w5], %[w5]\n\t"
            "adcs %[w6], %[w6], %[w6]\n\t"
            "adcs %[w7], %[w7], %[w7]\n\t"
            "adc %[c1], xzr, xzr\n\t"
            "subs xzr, %[c2], #1\n\t"
            "adcs %[w0], %[w0], %[s0]\n\t"
            "adcs %[w1], %[w1], %[s1]\n\t"
            "adcs %[w2], %[w2], %[s2]\n\t"
            "adcs %[w3], %[w3], %[s3]\n\t"
            "adcs %[w4], %[w4], %[s4]\n\t"
            "adcs %[w5], %[w5], %[s5]\n\t"
            "adcs %[w6], %[w6], %[s6]\n\t"
            "adcs %[w7], %[w7], %[s7]\n\t"
            "adc %[c2], xzr, xzr\n\t"
            "stp %[w0], %[w1], [%[t]]\n\t"
            "stp %[w2], %[w3], [%[t], #16]\n\t"
            "stp %[w4], %[w5], [%[t], #32]\n\t"
            "stp %[w6], %[w7], [%[t], #48]"
            : [c1] "+r"(c1), [c2] "+r"(c2), [w0] "=&r"(w0), [w1] "=&r"(w1), [w2] "=&r"(w2),
            [w3] "=&r"(w3), [w4] "=&r"(w4), [w5] "=&r"(w5), [w6] "=&r"(w6), [w7] "=&r"(w7),
            [s0] "=&r"(s0), [s1] "=&r"(s1), [s2] "=&r"(s2), [s3] "=&r"(s3), [s4] "=&r"(s4),
            [s5] "=&r"(s5), [s6] "=&r"(s6), [s7] "=&r"(s7)
            : [t] "r"(T), [x] "r"(x)
            : "cc", "memory");
    }
}

/// r = a + b for n = 4k words, returns the carry.
[[gnu::always_inline]] inline u64 add_n(u64* r, const u64* a, const u64* b, size_t n) noexcept
{
    u64 c = 0;
    for (size_t i = 0; i < n; i += 4)
    {
        u64 a0, a1, a2, a3, b0, b1, b2, b3;  // NOLINT
        asm volatile(
            "ldp %[a0], %[a1], [%[a]]\n\t"
            "ldp %[a2], %[a3], [%[a], #16]\n\t"
            "ldp %[b0], %[b1], [%[b]]\n\t"
            "ldp %[b2], %[b3], [%[b], #16]\n\t"
            "subs xzr, %[c], #1\n\t"
            "adcs %[a0], %[a0], %[b0]\n\t"
            "adcs %[a1], %[a1], %[b1]\n\t"
            "adcs %[a2], %[a2], %[b2]\n\t"
            "adcs %[a3], %[a3], %[b3]\n\t"
            "adc %[c], xzr, xzr\n\t"
            "stp %[a0], %[a1], [%[r]]\n\t"
            "stp %[a2], %[a3], [%[r], #16]"
            : [c] "+r"(c), [a0] "=&r"(a0), [a1] "=&r"(a1), [a2] "=&r"(a2), [a3] "=&r"(a3),
            [b0] "=&r"(b0), [b1] "=&r"(b1), [b2] "=&r"(b2), [b3] "=&r"(b3)
            : [r] "r"(r + i), [a] "r"(a + i), [b] "r"(b + i)
            : "cc", "memory");
    }
    return c;
}

#endif

/// The lowest chunk of a reduction-only block: computes q[] and the carry c[].
[[gnu::always_inline]] inline void redc_low(std::array<u64, 5>& c, std::array<u64, 4>& q,
    const u64* t, const u64* m, u64 m_inv) noexcept
{
    std::array<u64, 9> a;  // NOLINT
    copy_words<0, 0, 4>(a, t);
    a[4] = 0;
    q[0] = a[0] * m_inv;
    Row<4>::add_cancel_new<0>(a, m, q[0]);
    q[1] = a[1] * m_inv;
    Row<4>::add_cancel_new<1>(a, m, q[1]);
    q[2] = a[2] * m_inv;
    Row<4>::add_cancel_new<2>(a, m, q[2]);
    q[3] = a[3] * m_inv;
    Row<4>::add_cancel_new<3>(a, m, q[3]);
    copy_words<0, 4, 5>(c, a);
}

/// A chunk of a reduction-only block (CIOS without the products): shifts by 4 words.
template <bool LAST>
[[gnu::always_inline]] inline void redc_chunk(std::array<u64, 5>& c, const u64* t, u64* out,
    const u64* m, const std::array<u64, 4>& q, u64& top) noexcept
{
    std::array<u64, 9> a;  // NOLINT
    copy_words<0, 0, 5>(a, c);
    if constexpr (LAST)
        Row<4>::add_t_top(a, t, top);
    else
        Row<4>::add_t(a, t);
    Row<4>::add_new<0>(a, m, q[0]);
    out[0] = a[0];
    Row<4>::add_new<1>(a, m, q[1]);
    out[1] = a[1];
    Row<4>::add_new<2>(a, m, q[2]);
    out[2] = a[2];
    Row<4>::add_new<3>(a, m, q[3]);
    out[3] = a[3];
    if constexpr (LAST)
    {
        copy_words<4, 4, 4>(out, a);
        top = a[8];
    }
    else
        copy_words<0, 4, 5>(c, a);
}

/// t[0..n-1] + top = (t + Q⋅m) / 2^(64n) for t of n = 4k words, with Q making the low words 0.
[[gnu::always_inline]] inline void redc_lo(
    u64* t, const u64* m, u64 m_inv, size_t k, u64& top) noexcept
{
    for (size_t b = 0; b < k; ++b)
    {
        std::array<u64, 5> c;  // NOLINT
        std::array<u64, 4> q;  // NOLINT
        redc_low(c, q, t, m, m_inv);
        for (size_t j = 1; j + 1 < k; ++j)
            redc_chunk<false>(c, t + 4 * j, t + 4 * j - 4, m + 4 * j, q, top);
        redc_chunk<true>(c, t + 4 * (k - 1), t + 4 * (k - 1) - 4, m + 4 * (k - 1), q, top);
    }
}
}  // namespace

[[gnu::noinline]] void proto_sqr_amm(
    u64* r, const u64* x, const u64* m, u64 m_inv, size_t n) noexcept
{
    const auto k = n / 4;
    alignas(64) u64 T[2 * 128];
    std::memset(T, 0, n * sizeof(u64));
    triangle(T, x, k);
    double_add_squares(T, x, n);
    u64 top = 0;
    redc_lo(T, m, m_inv, k, top);
    const auto carry = add_n(r, T, T + n, n);
    if ((top | carry) != 0) [[unlikely]]
        sub({r, n}, {m, n});
}

/// Only the triangle and doubling: for timing the parts.
[[gnu::noinline]] void proto_sqr_part(
    u64* r, const u64* x, const u64* m, u64 m_inv, size_t n, int part) noexcept
{
    const auto k = n / 4;
    alignas(64) u64 T[2 * 128];
    std::memset(T, 0, n * sizeof(u64));
    if (part >= 1)
        triangle(T, x, k);
    if (part >= 2)
        double_add_squares(T, x, n);
    u64 top = 0;
    if (part >= 3)
        redc_lo(T, m, m_inv, k, top);
    for (size_t i = 0; i < n; ++i)
        r[i] = T[i] ^ T[n + i];
    (void)top;
}
}  // namespace evmone::crypto
