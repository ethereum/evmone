#include "ripemd160.hpp"

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

constexpr size_t N = 5;

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

void rmd160_compress(uint32_t* digest, const uint32_t* X) noexcept
{
    uint32_t z1[N];
    uint32_t z2[N];

    z1[0] = z2[0] = digest[0];
    z1[1] = z2[1] = digest[1];
    z1[2] = z2[2] = digest[2];
    z1[3] = z2[3] = digest[3];
    z1[4] = z2[4] = digest[4];

    subround<F, J, 0, 11, 8, k[0], k[5]>(z1, z2, X[0], X[5]);
    subround<F, J, 1, 14, 9, k[0], k[5]>(z1, z2, X[1], X[14]);
    subround<F, J, 2, 15, 9, k[0], k[5]>(z1, z2, X[2], X[7]);
    subround<F, J, 3, 12, 11, k[0], k[5]>(z1, z2, X[3], X[0]);
    subround<F, J, 4, 5, 13, k[0], k[5]>(z1, z2, X[4], X[9]);
    subround<F, J, 0, 8, 15, k[0], k[5]>(z1, z2, X[5], X[2]);
    subround<F, J, 1, 7, 15, k[0], k[5]>(z1, z2, X[6], X[11]);
    subround<F, J, 2, 9, 5, k[0], k[5]>(z1, z2, X[7], X[4]);
    subround<F, J, 3, 11, 7, k[0], k[5]>(z1, z2, X[8], X[13]);
    subround<F, J, 4, 13, 7, k[0], k[5]>(z1, z2, X[9], X[6]);
    subround<F, J, 0, 14, 8, k[0], k[5]>(z1, z2, X[10], X[15]);
    subround<F, J, 1, 15, 11, k[0], k[5]>(z1, z2, X[11], X[8]);
    subround<F, J, 2, 6, 14, k[0], k[5]>(z1, z2, X[12], X[1]);
    subround<F, J, 3, 7, 14, k[0], k[5]>(z1, z2, X[13], X[10]);
    subround<F, J, 4, 9, 12, k[0], k[5]>(z1, z2, X[14], X[3]);
    subround<F, J, 0, 8, 6, k[0], k[5]>(z1, z2, X[15], X[12]);

    subround<G, I, 1, 7, 9, k[1], k[6]>(z1, z2, X[7], X[6]);
    subround<G, I, 2, 6, 13, k[1], k[6]>(z1, z2, X[4], X[11]);
    subround<G, I, 3, 8, 15, k[1], k[6]>(z1, z2, X[13], X[3]);
    subround<G, I, 4, 13, 7, k[1], k[6]>(z1, z2, X[1], X[7]);
    subround<G, I, 0, 11, 12, k[1], k[6]>(z1, z2, X[10], X[0]);
    subround<G, I, 1, 9, 8, k[1], k[6]>(z1, z2, X[6], X[13]);
    subround<G, I, 2, 7, 9, k[1], k[6]>(z1, z2, X[15], X[5]);
    subround<G, I, 3, 15, 11, k[1], k[6]>(z1, z2, X[3], X[10]);
    subround<G, I, 4, 7, 7, k[1], k[6]>(z1, z2, X[12], X[14]);
    subround<G, I, 0, 12, 7, k[1], k[6]>(z1, z2, X[0], X[15]);
    subround<G, I, 1, 15, 12, k[1], k[6]>(z1, z2, X[9], X[8]);
    subround<G, I, 2, 9, 7, k[1], k[6]>(z1, z2, X[5], X[12]);
    subround<G, I, 3, 11, 6, k[1], k[6]>(z1, z2, X[2], X[4]);
    subround<G, I, 4, 7, 15, k[1], k[6]>(z1, z2, X[14], X[9]);
    subround<G, I, 0, 13, 13, k[1], k[6]>(z1, z2, X[11], X[1]);
    subround<G, I, 1, 12, 11, k[1], k[6]>(z1, z2, X[8], X[2]);

    subround<H, H, 2, 11, 9, k[2], k[7]>(z1, z2, X[3], X[15]);
    subround<H, H, 3, 13, 7, k[2], k[7]>(z1, z2, X[10], X[5]);
    subround<H, H, 4, 6, 15, k[2], k[7]>(z1, z2, X[14], X[1]);
    subround<H, H, 0, 7, 11, k[2], k[7]>(z1, z2, X[4], X[3]);
    subround<H, H, 1, 14, 8, k[2], k[7]>(z1, z2, X[9], X[7]);
    subround<H, H, 2, 9, 6, k[2], k[7]>(z1, z2, X[15], X[14]);
    subround<H, H, 3, 13, 6, k[2], k[7]>(z1, z2, X[8], X[6]);
    subround<H, H, 4, 15, 14, k[2], k[7]>(z1, z2, X[1], X[9]);
    subround<H, H, 0, 14, 12, k[2], k[7]>(z1, z2, X[2], X[11]);
    subround<H, H, 1, 8, 13, k[2], k[7]>(z1, z2, X[7], X[8]);
    subround<H, H, 2, 13, 5, k[2], k[7]>(z1, z2, X[0], X[12]);
    subround<H, H, 3, 6, 14, k[2], k[7]>(z1, z2, X[6], X[2]);
    subround<H, H, 4, 5, 13, k[2], k[7]>(z1, z2, X[13], X[10]);
    subround<H, H, 0, 12, 13, k[2], k[7]>(z1, z2, X[11], X[0]);
    subround<H, H, 1, 7, 7, k[2], k[7]>(z1, z2, X[5], X[4]);
    subround<H, H, 2, 5, 5, k[2], k[7]>(z1, z2, X[12], X[13]);

    subround<I, G, 3, 11, 15, k[3], k[8]>(z1, z2, X[1], X[8]);
    subround<I, G, 4, 12, 5, k[3], k[8]>(z1, z2, X[9], X[6]);
    subround<I, G, 0, 14, 8, k[3], k[8]>(z1, z2, X[11], X[4]);
    subround<I, G, 1, 15, 11, k[3], k[8]>(z1, z2, X[10], X[1]);
    subround<I, G, 2, 14, 14, k[3], k[8]>(z1, z2, X[0], X[3]);
    subround<I, G, 3, 15, 14, k[3], k[8]>(z1, z2, X[8], X[11]);
    subround<I, G, 4, 9, 6, k[3], k[8]>(z1, z2, X[12], X[15]);
    subround<I, G, 0, 8, 14, k[3], k[8]>(z1, z2, X[4], X[0]);
    subround<I, G, 1, 9, 6, k[3], k[8]>(z1, z2, X[13], X[5]);
    subround<I, G, 2, 14, 9, k[3], k[8]>(z1, z2, X[3], X[12]);
    subround<I, G, 3, 5, 12, k[3], k[8]>(z1, z2, X[7], X[2]);
    subround<I, G, 4, 6, 9, k[3], k[8]>(z1, z2, X[15], X[13]);
    subround<I, G, 0, 8, 12, k[3], k[8]>(z1, z2, X[14], X[9]);
    subround<I, G, 1, 6, 5, k[3], k[8]>(z1, z2, X[5], X[7]);
    subround<I, G, 2, 5, 15, k[3], k[8]>(z1, z2, X[6], X[10]);
    subround<I, G, 3, 12, 8, k[3], k[8]>(z1, z2, X[2], X[14]);

    subround<J, F, 4, 9, 8, k[4], k[9]>(z1, z2, X[4], X[12]);
    subround<J, F, 0, 15, 5, k[4], k[9]>(z1, z2, X[0], X[15]);
    subround<J, F, 1, 5, 12, k[4], k[9]>(z1, z2, X[5], X[10]);
    subround<J, F, 2, 11, 9, k[4], k[9]>(z1, z2, X[9], X[4]);
    subround<J, F, 3, 6, 12, k[4], k[9]>(z1, z2, X[7], X[1]);
    subround<J, F, 4, 8, 5, k[4], k[9]>(z1, z2, X[12], X[5]);
    subround<J, F, 0, 13, 14, k[4], k[9]>(z1, z2, X[2], X[8]);
    subround<J, F, 1, 12, 6, k[4], k[9]>(z1, z2, X[10], X[7]);
    subround<J, F, 2, 5, 8, k[4], k[9]>(z1, z2, X[14], X[6]);
    subround<J, F, 3, 12, 13, k[4], k[9]>(z1, z2, X[1], X[2]);
    subround<J, F, 4, 13, 6, k[4], k[9]>(z1, z2, X[3], X[13]);
    subround<J, F, 0, 14, 5, k[4], k[9]>(z1, z2, X[8], X[14]);
    subround<J, F, 1, 11, 15, k[4], k[9]>(z1, z2, X[11], X[0]);
    subround<J, F, 2, 8, 13, k[4], k[9]>(z1, z2, X[6], X[3]);
    subround<J, F, 3, 5, 11, k[4], k[9]>(z1, z2, X[15], X[9]);
    subround<J, F, 4, 6, 11, k[4], k[9]>(z1, z2, X[13], X[11]);


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
