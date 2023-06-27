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

template <decltype(F) Fn, size_t O, uint32_t S, uint32_t K>
inline void subround(uint32_t* z, uint32_t x)
{
    static constexpr auto ia = (0 + N - O) % N;
    static constexpr auto ib = (1 + N - O) % N;
    static constexpr auto ic = (2 + N - O) % N;
    static constexpr auto id = (3 + N - O) % N;
    static constexpr auto ie = (4 + N - O) % N;

    auto a = z[ia];
    auto b = z[ib];
    auto c = z[ic];
    auto d = z[id];
    auto e = z[ie];

    a += Fn(b, c, d) + x + K;
    a = rol(a, S) + e;
    c = rol(c, 10);

    z[ia] = a;
    z[ic] = c;
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

    subround<F, 0, 11, k[0]>(z1, X[0]);
    subround<F, 1, 14, k[0]>(z1, X[1]);
    subround<F, 2, 15, k[0]>(z1, X[2]);
    subround<F, 3, 12, k[0]>(z1, X[3]);
    subround<F, 4, 5, k[0]>(z1, X[4]);
    subround<F, 0, 8, k[0]>(z1, X[5]);
    subround<F, 1, 7, k[0]>(z1, X[6]);
    subround<F, 2, 9, k[0]>(z1, X[7]);
    subround<F, 3, 11, k[0]>(z1, X[8]);
    subround<F, 4, 13, k[0]>(z1, X[9]);
    subround<F, 0, 14, k[0]>(z1, X[10]);
    subround<F, 1, 15, k[0]>(z1, X[11]);
    subround<F, 2, 6, k[0]>(z1, X[12]);
    subround<F, 3, 7, k[0]>(z1, X[13]);
    subround<F, 4, 9, k[0]>(z1, X[14]);
    subround<F, 0, 8, k[0]>(z1, X[15]);

    subround<G, 1, 7, k[1]>(z1, X[7]);
    subround<G, 2, 6, k[1]>(z1, X[4]);
    subround<G, 3, 8, k[1]>(z1, X[13]);
    subround<G, 4, 13, k[1]>(z1, X[1]);
    subround<G, 0, 11, k[1]>(z1, X[10]);
    subround<G, 1, 9, k[1]>(z1, X[6]);
    subround<G, 2, 7, k[1]>(z1, X[15]);
    subround<G, 3, 15, k[1]>(z1, X[3]);
    subround<G, 4, 7, k[1]>(z1, X[12]);
    subround<G, 0, 12, k[1]>(z1, X[0]);
    subround<G, 1, 15, k[1]>(z1, X[9]);
    subround<G, 2, 9, k[1]>(z1, X[5]);
    subround<G, 3, 11, k[1]>(z1, X[2]);
    subround<G, 4, 7, k[1]>(z1, X[14]);
    subround<G, 0, 13, k[1]>(z1, X[11]);
    subround<G, 1, 12, k[1]>(z1, X[8]);

    subround<H, 2, 11, k[2]>(z1, X[3]);
    subround<H, 3, 13, k[2]>(z1, X[10]);
    subround<H, 4, 6, k[2]>(z1, X[14]);
    subround<H, 0, 7, k[2]>(z1, X[4]);
    subround<H, 1, 14, k[2]>(z1, X[9]);
    subround<H, 2, 9, k[2]>(z1, X[15]);
    subround<H, 3, 13, k[2]>(z1, X[8]);
    subround<H, 4, 15, k[2]>(z1, X[1]);
    subround<H, 0, 14, k[2]>(z1, X[2]);
    subround<H, 1, 8, k[2]>(z1, X[7]);
    subround<H, 2, 13, k[2]>(z1, X[0]);
    subround<H, 3, 6, k[2]>(z1, X[6]);
    subround<H, 4, 5, k[2]>(z1, X[13]);
    subround<H, 0, 12, k[2]>(z1, X[11]);
    subround<H, 1, 7, k[2]>(z1, X[5]);
    subround<H, 2, 5, k[2]>(z1, X[12]);

    subround<I, 3, 11, k[3]>(z1, X[1]);
    subround<I, 4, 12, k[3]>(z1, X[9]);
    subround<I, 0, 14, k[3]>(z1, X[11]);
    subround<I, 1, 15, k[3]>(z1, X[10]);
    subround<I, 2, 14, k[3]>(z1, X[0]);
    subround<I, 3, 15, k[3]>(z1, X[8]);
    subround<I, 4, 9, k[3]>(z1, X[12]);
    subround<I, 0, 8, k[3]>(z1, X[4]);
    subround<I, 1, 9, k[3]>(z1, X[13]);
    subround<I, 2, 14, k[3]>(z1, X[3]);
    subround<I, 3, 5, k[3]>(z1, X[7]);
    subround<I, 4, 6, k[3]>(z1, X[15]);
    subround<I, 0, 8, k[3]>(z1, X[14]);
    subround<I, 1, 6, k[3]>(z1, X[5]);
    subround<I, 2, 5, k[3]>(z1, X[6]);
    subround<I, 3, 12, k[3]>(z1, X[2]);

    subround<J, 4, 9, k[4]>(z1, X[4]);
    subround<J, 0, 15, k[4]>(z1, X[0]);
    subround<J, 1, 5, k[4]>(z1, X[5]);
    subround<J, 2, 11, k[4]>(z1, X[9]);
    subround<J, 3, 6, k[4]>(z1, X[7]);
    subround<J, 4, 8, k[4]>(z1, X[12]);
    subround<J, 0, 13, k[4]>(z1, X[2]);
    subround<J, 1, 12, k[4]>(z1, X[10]);
    subround<J, 2, 5, k[4]>(z1, X[14]);
    subround<J, 3, 12, k[4]>(z1, X[1]);
    subround<J, 4, 13, k[4]>(z1, X[3]);
    subround<J, 0, 14, k[4]>(z1, X[8]);
    subround<J, 1, 11, k[4]>(z1, X[11]);
    subround<J, 2, 8, k[4]>(z1, X[6]);
    subround<J, 3, 5, k[4]>(z1, X[15]);
    subround<J, 4, 6, k[4]>(z1, X[13]);

    subround<J, 0, 8, k[5]>(z2, X[5]);
    subround<J, 1, 9, k[5]>(z2, X[14]);
    subround<J, 2, 9, k[5]>(z2, X[7]);
    subround<J, 3, 11, k[5]>(z2, X[0]);
    subround<J, 4, 13, k[5]>(z2, X[9]);
    subround<J, 0, 15, k[5]>(z2, X[2]);
    subround<J, 1, 15, k[5]>(z2, X[11]);
    subround<J, 2, 5, k[5]>(z2, X[4]);
    subround<J, 3, 7, k[5]>(z2, X[13]);
    subround<J, 4, 7, k[5]>(z2, X[6]);
    subround<J, 0, 8, k[5]>(z2, X[15]);
    subround<J, 1, 11, k[5]>(z2, X[8]);
    subround<J, 2, 14, k[5]>(z2, X[1]);
    subround<J, 3, 14, k[5]>(z2, X[10]);
    subround<J, 4, 12, k[5]>(z2, X[3]);
    subround<J, 0, 6, k[5]>(z2, X[12]);

    subround<I, 1, 9, k[6]>(z2, X[6]);
    subround<I, 2, 13, k[6]>(z2, X[11]);
    subround<I, 3, 15, k[6]>(z2, X[3]);
    subround<I, 4, 7, k[6]>(z2, X[7]);
    subround<I, 0, 12, k[6]>(z2, X[0]);
    subround<I, 1, 8, k[6]>(z2, X[13]);
    subround<I, 2, 9, k[6]>(z2, X[5]);
    subround<I, 3, 11, k[6]>(z2, X[10]);
    subround<I, 4, 7, k[6]>(z2, X[14]);
    subround<I, 0, 7, k[6]>(z2, X[15]);
    subround<I, 1, 12, k[6]>(z2, X[8]);
    subround<I, 2, 7, k[6]>(z2, X[12]);
    subround<I, 3, 6, k[6]>(z2, X[4]);
    subround<I, 4, 15, k[6]>(z2, X[9]);
    subround<I, 0, 13, k[6]>(z2, X[1]);
    subround<I, 1, 11, k[6]>(z2, X[2]);

    subround<H, 2, 9, k[7]>(z2, X[15]);
    subround<H, 3, 7, k[7]>(z2, X[5]);
    subround<H, 4, 15, k[7]>(z2, X[1]);
    subround<H, 0, 11, k[7]>(z2, X[3]);
    subround<H, 1, 8, k[7]>(z2, X[7]);
    subround<H, 2, 6, k[7]>(z2, X[14]);
    subround<H, 3, 6, k[7]>(z2, X[6]);
    subround<H, 4, 14, k[7]>(z2, X[9]);
    subround<H, 0, 12, k[7]>(z2, X[11]);
    subround<H, 1, 13, k[7]>(z2, X[8]);
    subround<H, 2, 5, k[7]>(z2, X[12]);
    subround<H, 3, 14, k[7]>(z2, X[2]);
    subround<H, 4, 13, k[7]>(z2, X[10]);
    subround<H, 0, 13, k[7]>(z2, X[0]);
    subround<H, 1, 7, k[7]>(z2, X[4]);
    subround<H, 2, 5, k[7]>(z2, X[13]);

    subround<G, 3, 15, k[8]>(z2, X[8]);
    subround<G, 4, 5, k[8]>(z2, X[6]);
    subround<G, 0, 8, k[8]>(z2, X[4]);
    subround<G, 1, 11, k[8]>(z2, X[1]);
    subround<G, 2, 14, k[8]>(z2, X[3]);
    subround<G, 3, 14, k[8]>(z2, X[11]);
    subround<G, 4, 6, k[8]>(z2, X[15]);
    subround<G, 0, 14, k[8]>(z2, X[0]);
    subround<G, 1, 6, k[8]>(z2, X[5]);
    subround<G, 2, 9, k[8]>(z2, X[12]);
    subround<G, 3, 12, k[8]>(z2, X[2]);
    subround<G, 4, 9, k[8]>(z2, X[13]);
    subround<G, 0, 12, k[8]>(z2, X[9]);
    subround<G, 1, 5, k[8]>(z2, X[7]);
    subround<G, 2, 15, k[8]>(z2, X[10]);
    subround<G, 3, 8, k[8]>(z2, X[14]);

    subround<F, 4, 8, k[9]>(z2, X[12]);
    subround<F, 0, 5, k[9]>(z2, X[15]);
    subround<F, 1, 12, k[9]>(z2, X[10]);
    subround<F, 2, 9, k[9]>(z2, X[4]);
    subround<F, 3, 12, k[9]>(z2, X[1]);
    subround<F, 4, 5, k[9]>(z2, X[5]);
    subround<F, 0, 14, k[9]>(z2, X[8]);
    subround<F, 1, 6, k[9]>(z2, X[7]);
    subround<F, 2, 8, k[9]>(z2, X[6]);
    subround<F, 3, 13, k[9]>(z2, X[2]);
    subround<F, 4, 6, k[9]>(z2, X[13]);
    subround<F, 0, 5, k[9]>(z2, X[14]);
    subround<F, 1, 15, k[9]>(z2, X[0]);
    subround<F, 2, 13, k[9]>(z2, X[3]);
    subround<F, 3, 11, k[9]>(z2, X[9]);
    subround<F, 4, 11, k[9]>(z2, X[11]);

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
