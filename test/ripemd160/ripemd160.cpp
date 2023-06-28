#include "ripemd160.hpp"
#include <cstddef>
#include <cstdint>
#include <utility>

inline uint32_t rol(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

inline uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
    return (x ^ y ^ z);
}

inline uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
    return (z ^ (x & (y ^ z)));
}

inline uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
    return (z ^ (x | ~y));
}

inline uint32_t I(uint32_t x, uint32_t y, uint32_t z)
{
    return (y ^ (z & (x ^ y)));
}

inline uint32_t J(uint32_t x, uint32_t y, uint32_t z)
{
    return (x ^ (y | ~z));
}

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
    /* s ( 0..15) = */ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,  //
    /* s (16..31) = */ 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,  //
    /* s (32..47) = */ 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,  //
    /* s (48..63) = */ 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,  //
    /* s (64..79) = */ 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,  //
    /* s′( 0..15) = */ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,  //
    /* s′(16..31) = */ 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,  //
    /* s′(32..47) = */ 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,  //
    /* s′(48..63) = */ 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,  //
    /* s′(64..79) = */ 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,  //
};

template <decltype(F) Fn1, decltype(F) Fn2, size_t O, uint32_t S1, uint32_t S2, uint32_t K1,
    uint32_t K2>
inline void subround(uint32_t* z1, uint32_t* z2, uint32_t x1, uint32_t x2)
{
    static constexpr auto ia = (0 + N - O) % N;
    static constexpr auto ib = (1 + N - O) % N;
    static constexpr auto ic = (2 + N - O) % N;
    static constexpr auto id = (3 + N - O) % N;
    static constexpr auto ie = (4 + N - O) % N;

    auto a1 = z1[ia];
    auto b1 = z1[ib];
    auto c1 = z1[ic];
    auto d1 = z1[id];
    auto e1 = z1[ie];

    a1 += Fn1(b1, c1, d1) + x1 + K1;
    a1 = rol(a1, S1) + e1;
    c1 = rol(c1, 10);

    z1[ia] = a1;
    z1[ic] = c1;

    auto a2 = z2[ia];
    auto b2 = z2[ib];
    auto c2 = z2[ic];
    auto d2 = z2[id];
    auto e2 = z2[ie];

    a2 += Fn2(b2, c2, d2) + x2 + K2;
    a2 = rol(a2, S2) + e2;
    c2 = rol(c2, 10);

    z2[ia] = a2;
    z2[ic] = c2;
}

template <size_t Rn, decltype(F) Fn1, decltype(F) Fn2, std::size_t... I>
[[gnu::always_inline]] inline void round_impl(uint32_t* z1, uint32_t* z2, const uint32_t* X,
    std::integer_sequence<std::size_t, I...>) noexcept
{
    (subround<Fn1, Fn2, (I + Rn) % N, s[Rn * 16 + I], s[Rn * 16 + I + 80], k[Rn], k[Rn + 5]>(
         z1, z2, X[r[Rn * 16 + I]], X[r[Rn * 16 + I + 80]]),
        ...);
}

template <size_t Rn, decltype(F) Fn1, decltype(F) Fn2>
[[gnu::always_inline]] inline void round(uint32_t* z1, uint32_t* z2, const uint32_t* X) noexcept
{
    round_impl<Rn, Fn1, Fn2>(z1, z2, X, std::make_index_sequence<16>{});
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

    round<0, F, J>(z1, z2, X);
    round<1, G, I>(z1, z2, X);
    round<2, H, H>(z1, z2, X);
    round<3, I, G>(z1, z2, X);
    round<4, J, F>(z1, z2, X);

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
