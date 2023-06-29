#include "ripemd160.hpp"
#include <bit>
#include <cstddef>
#include <cstdint>
#include <utility>

using FT = uint32_t (*)(uint32_t, uint32_t, uint32_t) noexcept;

static constexpr FT ft[] = {
    // f₁(x, y, z) = x ⊕ y ⊕ z
    [](uint32_t x, uint32_t y, uint32_t z) noexcept { return x ^ y ^ z; },

    // f₂(x, y, z) = (x ∧ y) ∨ (¬x ∧ z) ⇔ ((y ⊕ z) ∧ x) ⊕ z
    [](uint32_t x, uint32_t y, uint32_t z) noexcept { return ((y ^ z) & x) ^ z; },

    // f₃(x, y, z) = (x ∨ ¬y) ⊕ z
    [](uint32_t x, uint32_t y, uint32_t z) noexcept { return (x | ~y) ^ z; },

    // f₄(x, y, z) = (x ∧ z) ∨ (y ∧ ¬z) ⇔ ((x ⊕ y) ∧ z) ⊕ y
    [](uint32_t x, uint32_t y, uint32_t z) noexcept { return ((x ^ y) & z) ^ y; },

    // f₅(x, y, z) = x ⊕ (y ∨ ¬z)
    [](uint32_t x, uint32_t y, uint32_t z) noexcept { return x ^ (y | ~z); },
};

constexpr uint32_t k[] = {
    0,
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xa953fd4e,
    0x50a28be6,
    0x5c4dd124,
    0x6d703ef3,
    0x7a6d76e9,
    0,
};

static constexpr size_t N = 5;

/// Selection of message word.
static constexpr size_t r[] = {
    /*r ( 0..15) = */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  //
    /*r (16..31) = */ 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,  //
    /*r (32..47) = */ 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,  //
    /*r (48..63) = */ 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,  //
    /*r (64..79) = */ 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,  //
    /*r′( 0..15) = */ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,  //
    /*r′(16..31) = */ 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,  //
    /*r′(32..47) = */ 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,  //
    /*r′(48..63) = */ 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,  //
    /*r′(64..79) = */ 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,  //
};

/// Amount for rotate left.
static constexpr uint32_t s[] = {
    /* s ( 0..15) = */ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    /* s (16..31) = */ 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    /* s (32..47) = */ 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    /* s (48..63) = */ 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    /* s (64..79) = */ 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    /* s′( 0..15) = */ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    /* s′(16..31) = */ 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    /* s′(32..47) = */ 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    /* s′(48..63) = */ 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    /* s′(64..79) = */ 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,  //
};

template <size_t J>
inline void subround(uint32_t* z1, uint32_t* z2, const uint32_t* x)
{
    static constexpr auto Rn = J / 16;
    static constexpr auto K1 = k[Rn];
    static constexpr auto K2 = k[Rn + N];
    static constexpr auto S1 = s[J];
    static constexpr auto S2 = s[J + 80];
    static constexpr auto Fn1 = ft[Rn];
    static constexpr auto Fn2 = ft[N - 1 - Rn];

    const auto x1 = x[r[J]];
    const auto x2 = x[r[J + 80]];

    auto a1 = z1[0];
    auto b1 = z1[1];
    auto c1 = z1[2];
    auto d1 = z1[3];
    auto e1 = z1[4];

    z1[0] = e1;
    z1[1] = std::rotl(a1 + Fn1(b1, c1, d1) + x1 + K1, S1) + e1;
    z1[2] = b1;
    z1[3] = std::rotl(c1, 10);
    z1[4] = d1;

    auto a2 = z2[0];
    auto b2 = z2[1];
    auto c2 = z2[2];
    auto d2 = z2[3];
    auto e2 = z2[4];

    z2[0] = e2;
    z2[1] = std::rotl(a2 + Fn2(b2, c2, d2) + x2 + K2, S2) + e2;
    z2[2] = b2;
    z2[3] = std::rotl(c2, 10);
    z2[4] = d2;
}

template <std::size_t... I>
[[gnu::always_inline]] inline void round_impl(uint32_t* z1, uint32_t* z2, const uint32_t* X,
    std::integer_sequence<std::size_t, I...>) noexcept
{
    (subround<I>(z1, z2, X), ...);
}

[[gnu::always_inline]] inline void round(uint32_t* z1, uint32_t* z2, const uint32_t* X) noexcept
{
    round_impl(z1, z2, X, std::make_index_sequence<80>{});
}

void rmd160_compress(uint32_t* digest, const uint32_t* X) noexcept
{
    uint32_t z1[N];
    uint32_t z2[N];

    z1[0] = z2[0] = digest[0];
    z1[1] = z2[1] = digest[1];
    z1[2] = z2[2] = digest[2];
    z1[3] = z2[3] = digest[3];
    z1[4] = z2[4] = digest[4];

    round(z1, z2, X);

    auto t = digest[1] + z1[2] + z2[3];
    digest[1] = digest[2] + z1[3] + z2[4];
    digest[2] = digest[3] + z1[4] + z2[0];
    digest[3] = digest[4] + z1[0] + z2[1];
    digest[4] = digest[0] + z1[1] + z2[2];
    digest[0] = t;
}

/*
 *  puts bytes from strptr into X and pad out; appends length
 *  and finally, compresses the last block(s)
 *  note: length in bits == 8 * lswlen.
 *  note: there are (lswlen mod 64) bytes left in strptr.
 */
static inline void rmd160_finish(uint32_t* MDbuf, uint8_t const* strptr, uint32_t lswlen)
{
    unsigned int i; /* counter       */
    uint32_t X[16]; /* message words */

    __builtin_memset(X, 0, 16 * sizeof(uint32_t));

    /* put bytes from strptr into X */
    for (i = 0; i < (lswlen & 63); i++)
    {
        /* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
        X[i >> 2] ^= (uint32_t)*strptr++ << (8 * (i & 3));
    }

    /* append the bit m_n == 1 */
    X[(lswlen >> 2) & 15] ^= (uint32_t)1 << (8 * (lswlen & 3) + 7);

    if ((lswlen & 63) > 55)
    {
        /* length goes to next block */
        rmd160_compress(MDbuf, X);
        __builtin_memset(X, 0, 16 * sizeof(uint32_t));
    }

    /* append length in bits*/
    X[14] = lswlen << 3;
    X[15] = lswlen >> 29;
    rmd160_compress(MDbuf, X);
}

static inline uint32_t load32(const void* src)
{
    uint32_t w;
    __builtin_memcpy(&w, src, sizeof w);
    return w;
}


static inline void rmd160_init(uint32_t* MDbuf)
{
    MDbuf[0] = 0x67452301UL;
    MDbuf[1] = 0xefcdab89UL;
    MDbuf[2] = 0x98badcfeUL;
    MDbuf[3] = 0x10325476UL;
    MDbuf[4] = 0xc3d2e1f0UL;
}

void ripemd160(uint8_t out[20], const uint8_t* ptr, size_t len)
{
    uint32_t buf[160 / 32];

    rmd160_init(buf);

    uint32_t current[16];
    for (size_t remaining = len; remaining >= 64; remaining -= 64)
    {
        for (unsigned i = 0; i < 16; ++i)
        {
            current[i] = load32(ptr);
            ptr += 4;
        }
        rmd160_compress(buf, current);
    }

    rmd160_finish(buf, ptr, static_cast<uint32_t>(len));

    for (unsigned i = 0; i < 20; i += 4)
    {
        out[i] = static_cast<uint8_t>(buf[i >> 2]);
        out[i + 1] = static_cast<uint8_t>(buf[i >> 2] >> 8);
        out[i + 2] = static_cast<uint8_t>(buf[i >> 2] >> 16);
        out[i + 3] = static_cast<uint8_t>(buf[i >> 2] >> 24);
    }
}
