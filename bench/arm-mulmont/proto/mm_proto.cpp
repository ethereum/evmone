// Prototype 4-word AMM procs on top of the production rows (x86-64 and AArch64):
// proto_sqr4: x² in registers, the low half reduced by 4 cancelling rows, the high half added last.
// proto_ahead4: CIOS in the order of blst, the product row i+1 before the reduction row i.
#include MM_SRC

namespace evmone::crypto
{
namespace
{
#ifdef __x86_64__
/// Sets t[0..7] = x[]².
[[gnu::always_inline]] inline void square4(std::array<uint64_t, 9>& t, const uint64_t* x) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("movq (%[x]), %%rdx\n\t"
        "mulxq 8(%[x]), %[t1], %[t2]\n\t"
        "mulxq 16(%[x]), %[lo], %[t3]\n\t"
        "addq %[lo], %[t2]\n\t"
        "mulxq 24(%[x]), %[lo], %[t4]\n\t"
        "adcq %[lo], %[t3]\n\t"
        "adcq $0, %[t4]\n\t"
        "movq 8(%[x]), %%rdx\n\t"
        "xorl %k[t5], %k[t5]\n\t"
        "mulxq 16(%[x]), %[lo], %[hi]\n\t"
        "adcxq %[lo], %[t3]\n\t"
        "adoxq %[hi], %[t4]\n\t"
        "mulxq 24(%[x]), %[lo], %[hi]\n\t"
        "adcxq %[lo], %[t4]\n\t"
        "adoxq %[hi], %[t5]\n\t"
        "adcq $0, %[t5]\n\t"
        "movq 16(%[x]), %%rdx\n\t"
        "mulxq 24(%[x]), %[lo], %[t6]\n\t"
        "addq %[lo], %[t5]\n\t"
        "adcq $0, %[t6]\n\t"
        "movq (%[x]), %%rdx\n\t"
        "xorl %k[t7], %k[t7]\n\t"
        "mulxq %%rdx, %[t0], %[hi]\n\t"
        "adcxq %[t1], %[t1]\n\t"
        "adoxq %[hi], %[t1]\n\t"
        "movq 8(%[x]), %%rdx\n\t"
        "mulxq %%rdx, %[lo], %[hi]\n\t"
        "adcxq %[t2], %[t2]\n\t"
        "adoxq %[lo], %[t2]\n\t"
        "adcxq %[t3], %[t3]\n\t"
        "adoxq %[hi], %[t3]\n\t"
        "movq 16(%[x]), %%rdx\n\t"
        "mulxq %%rdx, %[lo], %[hi]\n\t"
        "adcxq %[t4], %[t4]\n\t"
        "adoxq %[lo], %[t4]\n\t"
        "adcxq %[t5], %[t5]\n\t"
        "adoxq %[hi], %[t5]\n\t"
        "movq 24(%[x]), %%rdx\n\t"
        "mulxq %%rdx, %[lo], %[hi]\n\t"
        "adcxq %[t6], %[t6]\n\t"
        "adoxq %[lo], %[t6]\n\t"
        "adcxq %[t7], %[t7]\n\t"
        "adoxq %[hi], %[t7]"
        : [t0] "=&r"(t[0]), [t1] "=&r"(t[1]), [t2] "=&r"(t[2]), [t3] "=&r"(t[3]),
        [t4] "=&r"(t[4]), [t5] "=&r"(t[5]), [t6] "=&r"(t[6]), [t7] "=&r"(t[7]), [lo] "=&r"(lo),
        [hi] "=&r"(hi)
        : [x] "r"(x), "m"(words(x))
        : "rdx", "cc");
}

/// a[4..7] += h[]; returns the carry.
[[gnu::always_inline]] inline uint64_t add_high4(
    std::array<uint64_t, 9>& a, const std::array<uint64_t, 4>& h) noexcept
{
    uint64_t c = 0;
    asm("addq %[h0], %[a0]\n\tadcq %[h1], %[a1]\n\tadcq %[h2], %[a2]\n\tadcq %[h3], %[a3]\n\t"
        "setc %b[c]"
        : [a0] "+r"(a[4]), [a1] "+r"(a[5]), [a2] "+r"(a[6]), [a3] "+r"(a[7]), [c] "+r"(c)
        : [h0] "r"(h[0]), [h1] "r"(h[1]), [h2] "r"(h[2]), [h3] "r"(h[3])
        : "cc");
    return c;
}

/// Adds m[]⋅q to a[P..P+4] where q makes a[P] 0, the carry goes to a[P+5] and ripples to a[P+6].
template <size_t P, size_t K>
[[gnu::always_inline]] inline void cancel_ripple2(
    std::array<uint64_t, K>& a, const uint64_t* m, uint64_t q) noexcept
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    asm("xorl %k[lo], %k[lo]\n\t"
        "mulxq (%[m]), %[lo], %[hi]\n\tadcxq %[lo], %[a0]\n\tadoxq %[hi], %[a1]\n\t"
        "mulxq 8(%[m]), %[lo], %[hi]\n\tadcxq %[lo], %[a1]\n\tadoxq %[hi], %[a2]\n\t"
        "mulxq 16(%[m]), %[lo], %[hi]\n\tadcxq %[lo], %[a2]\n\tadoxq %[hi], %[a3]\n\t"
        "mulxq 24(%[m]), %[lo], %[hi]\n\tadcxq %[lo], %[a3]\n\tadcxq %[a0], %[hi]\n\t"
        "adoxq %[hi], %[a4]\n\tadoxq %[a0], %[a5]\n\tadoxq %[a0], %[a6]"
        : [a0] "+r"(a[P]), [a1] "+r"(a[P + 1]), [a2] "+r"(a[P + 2]), [a3] "+r"(a[P + 3]),
        [a4] "+r"(a[P + 4]), [a5] "+r"(a[P + 5]), [a6] "+r"(a[P + 6]), [lo] "=&r"(lo),
        [hi] "=&r"(hi)
        : [m] "r"(m), "d"(q), "m"(words(m))
        : "cc");
}
#else
/// Sets t[0..7] = x[]².
[[gnu::always_inline]] inline void square4(std::array<uint64_t, 9>& t, const uint64_t* xp) noexcept
{
    const uint64_t x0 = xp[0];
    const uint64_t x1 = xp[1];
    const uint64_t x2 = xp[2];
    const uint64_t x3 = xp[3];
    uint64_t l = 0;
    uint64_t h = 0;
    asm("mul %[t1], %[x0], %[x1]\n\t"
        "umulh %[t2], %[x0], %[x1]\n\t"
        "mul %[l], %[x0], %[x2]\n\t"
        "umulh %[t3], %[x0], %[x2]\n\t"
        "adds %[t2], %[t2], %[l]\n\t"
        "mul %[l], %[x0], %[x3]\n\t"
        "umulh %[t4], %[x0], %[x3]\n\t"
        "adcs %[t3], %[t3], %[l]\n\t"
        "adc %[t4], %[t4], xzr\n\t"
        "mul %[l], %[x1], %[x2]\n\t"
        "umulh %[h], %[x1], %[x2]\n\t"
        "adds %[t3], %[t3], %[l]\n\t"
        "adcs %[t4], %[t4], %[h]\n\t"
        "adc %[t5], xzr, xzr\n\t"
        "mul %[l], %[x1], %[x3]\n\t"
        "umulh %[h], %[x1], %[x3]\n\t"
        "adds %[t4], %[t4], %[l]\n\t"
        "adc %[t5], %[t5], %[h]\n\t"
        "mul %[l], %[x2], %[x3]\n\t"
        "umulh %[t6], %[x2], %[x3]\n\t"
        "adds %[t5], %[t5], %[l]\n\t"
        "adc %[t6], %[t6], xzr\n\t"
        "lsr %[t7], %[t6], #63\n\t"
        "extr %[t6], %[t6], %[t5], #63\n\t"
        "extr %[t5], %[t5], %[t4], #63\n\t"
        "extr %[t4], %[t4], %[t3], #63\n\t"
        "extr %[t3], %[t3], %[t2], #63\n\t"
        "extr %[t2], %[t2], %[t1], #63\n\t"
        "lsl %[t1], %[t1], #1\n\t"
        "mul %[t0], %[x0], %[x0]\n\t"
        "umulh %[h], %[x0], %[x0]\n\t"
        "adds %[t1], %[t1], %[h]\n\t"
        "mul %[l], %[x1], %[x1]\n\t"
        "umulh %[h], %[x1], %[x1]\n\t"
        "adcs %[t2], %[t2], %[l]\n\t"
        "adcs %[t3], %[t3], %[h]\n\t"
        "mul %[l], %[x2], %[x2]\n\t"
        "umulh %[h], %[x2], %[x2]\n\t"
        "adcs %[t4], %[t4], %[l]\n\t"
        "adcs %[t5], %[t5], %[h]\n\t"
        "mul %[l], %[x3], %[x3]\n\t"
        "umulh %[h], %[x3], %[x3]\n\t"
        "adcs %[t6], %[t6], %[l]\n\t"
        "adc %[t7], %[t7], %[h]"
        : [t0] "=&r"(t[0]), [t1] "=&r"(t[1]), [t2] "=&r"(t[2]), [t3] "=&r"(t[3]),
        [t4] "=&r"(t[4]), [t5] "=&r"(t[5]), [t6] "=&r"(t[6]), [t7] "=&r"(t[7]), [l] "=&r"(l),
        [h] "=&r"(h)
        : [x0] "r"(x0), [x1] "r"(x1), [x2] "r"(x2), [x3] "r"(x3)
        : "cc");
}

/// a[4..7] += h[]; returns the carry.
[[gnu::always_inline]] inline uint64_t add_high4(
    std::array<uint64_t, 9>& a, const std::array<uint64_t, 4>& h) noexcept
{
    uint64_t c = 0;
    asm("adds %[a0], %[a0], %[h0]\n\tadcs %[a1], %[a1], %[h1]\n\tadcs %[a2], %[a2], %[h2]\n\t"
        "adcs %[a3], %[a3], %[h3]\n\tcset %[c], cs"
        : [a0] "+r"(a[4]), [a1] "+r"(a[5]), [a2] "+r"(a[6]), [a3] "+r"(a[7]), [c] "=r"(c)
        : [h0] "r"(h[0]), [h1] "r"(h[1]), [h2] "r"(h[2]), [h3] "r"(h[3])
        : "cc");
    return c;
}

/// Adds m[]⋅q to a[P..P+4] where q makes a[P] 0, the carry goes to a[P+5] and ripples to a[P+6].
template <size_t P, size_t K>
[[gnu::always_inline]] inline void cancel_ripple2(
    std::array<uint64_t, K>& a, const uint64_t* m, uint64_t q) noexcept
{
    std::array<uint64_t, 4> t;
    asm("mul %[t1], %[s1], %[y]\n\t"
        "mul %[t2], %[s2], %[y]\n\t"
        "mul %[t3], %[s3], %[y]\n\t"
        "subs xzr, %[a0], #1\n\t"
        "adcs %[a1], %[a1], %[t1]\n\t"
        "adcs %[a2], %[a2], %[t2]\n\t"
        "adcs %[a3], %[a3], %[t3]\n\t"
        "umulh %[t0], %[s0], %[y]\n\t"
        "umulh %[t1], %[s1], %[y]\n\t"
        "umulh %[t2], %[s2], %[y]\n\t"
        "umulh %[t3], %[s3], %[y]\n\t"
        "adc %[t3], %[t3], xzr\n\t"
        "adds %[a1], %[a1], %[t0]\n\t"
        "adcs %[a2], %[a2], %[t1]\n\t"
        "adcs %[a3], %[a3], %[t2]\n\t"
        "adcs %[a4], %[a4], %[t3]\n\t"
        "adcs %[a5], %[a5], xzr\n\t"
        "adc %[a6], %[a6], xzr"
        : [a1] "+r"(a[P + 1]), [a2] "+r"(a[P + 2]), [a3] "+r"(a[P + 3]), [a4] "+r"(a[P + 4]),
        [a5] "+r"(a[P + 5]), [a6] "+r"(a[P + 6]), [t0] "=&r"(t[0]), [t1] "=&r"(t[1]),
        [t2] "=&r"(t[2]), [t3] "=&r"(t[3])
        : [a0] "r"(a[P]), [s0] "r"(m[0]), [s1] "r"(m[1]), [s2] "r"(m[2]), [s3] "r"(m[3]),
        [y] "r"(q)
        : "cc");
}
#endif

}  // namespace

EVMONE_PRESERVE_NONE void proto_sqr4(
    uint64_t* r, const uint64_t* x, const uint64_t* m, uint64_t m_inv) noexcept
{
    std::array<uint64_t, 9> a;  // NOLINT(*-member-init)
    square4(a, x);
#ifdef __aarch64__
    std::array<uint64_t, 4> mw;  // NOLINT(*-member-init): copied below.
    copy_words<0, 0, 4>(mw, m);
    m = mw.data();
#endif
    const std::array<uint64_t, 4> h{a[4], a[5], a[6], a[7]};
    a[4] = 0;
    Row<4>::add_cancel_new<0>(a, m, mul_q(a[0], m_inv));
    Row<4>::add_cancel_new<1>(a, m, mul_q(a[1], m_inv));
    Row<4>::add_cancel_new<2>(a, m, mul_q(a[2], m_inv));
    Row<4>::add_cancel_new<3>(a, m, mul_q(a[3], m_inv));
    if (add_high4(a, h) != 0) [[unlikely]]
    {
        std::array<uint64_t, 4> u{a[4], a[5], a[6], a[7]};
        sub_words(u, m, std::make_index_sequence<4>{});
        copy_words<0, 0, 4>(r, u);
        return;
    }
    copy_words<0, 4, 4>(r, a);
}

EVMONE_PRESERVE_NONE void proto_ahead4(uint64_t* r, const uint64_t* x, const uint64_t* y,
    const uint64_t* m, uint64_t m_inv) noexcept
{
#ifdef __aarch64__
    std::array<uint64_t, 4> xw;  // NOLINT(*-member-init): copied below.
    std::array<uint64_t, 4> mw;  // NOLINT(*-member-init): copied below.
    std::array<uint64_t, 4> yw;  // NOLINT(*-member-init): copied below.
    copy_words<0, 0, 4>(xw, x);
    copy_words<0, 0, 4>(mw, m);
    copy_words<0, 0, 4>(yw, y);
    x = xw.data();
    m = mw.data();
    y = yw.data();
#endif
    std::array<uint64_t, 9> a;  // NOLINT(*-member-init)
    Row<4>::set<0>(a, x, y[0]);
    a[5] = 0;
    const auto q0 = mul_q(a[0], m_inv);
    Row<4>::add_new<1>(a, x, y[1]);  // a[1..5], new a[6]
    cancel_ripple2<0>(a, m, q0);
    const auto q1 = mul_q(a[1], m_inv);
    Row<4>::add_new<2>(a, x, y[2]);
    cancel_ripple2<1>(a, m, q1);
    const auto q2 = mul_q(a[2], m_inv);
    Row<4>::add_new<3>(a, x, y[3]);
    cancel_ripple2<2>(a, m, q2);
    Row<4>::add_cancel<3>(a, m, mul_q(a[3], m_inv));
    std::array<uint64_t, 5> c{a[4], a[5], a[6], a[7], a[8]};
    if (c[4] != 0) [[unlikely]]
        sub_words(c, m, std::make_index_sequence<4>{});
    copy_words<0, 0, 4>(r, c);
}
}  // namespace evmone::crypto
