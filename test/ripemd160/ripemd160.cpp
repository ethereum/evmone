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

#define k0 0
#define k1 0x5a827999UL
#define k2 0x6ed9eba1UL
#define k3 0x8f1bbcdcUL
#define k4 0xa953fd4eUL
#define k5 0x50a28be6UL
#define k6 0x5c4dd124UL
#define k7 0x6d703ef3UL
#define k8 0x7a6d76e9UL
#define k9 0

#define Subround(f, a, b, c, d, e, x, s, k) \
    a += f(b, c, d) + x + k;                \
    a = rol(a, s) + e;                      \
    c = rol(c, 10)

static inline void rmd160_compress(uint32_t* digest, const uint32_t* X)
{
    uint32_t a1, b1, c1, d1, e1, a2, b2, c2, d2, e2;
    a1 = a2 = digest[0];
    b1 = b2 = digest[1];
    c1 = c2 = digest[2];
    d1 = d2 = digest[3];
    e1 = e2 = digest[4];

    Subround(F, a1, b1, c1, d1, e1, X[0], 11, k0);
    Subround(F, e1, a1, b1, c1, d1, X[1], 14, k0);
    Subround(F, d1, e1, a1, b1, c1, X[2], 15, k0);
    Subround(F, c1, d1, e1, a1, b1, X[3], 12, k0);
    Subround(F, b1, c1, d1, e1, a1, X[4], 5, k0);
    Subround(F, a1, b1, c1, d1, e1, X[5], 8, k0);
    Subround(F, e1, a1, b1, c1, d1, X[6], 7, k0);
    Subround(F, d1, e1, a1, b1, c1, X[7], 9, k0);
    Subround(F, c1, d1, e1, a1, b1, X[8], 11, k0);
    Subround(F, b1, c1, d1, e1, a1, X[9], 13, k0);
    Subround(F, a1, b1, c1, d1, e1, X[10], 14, k0);
    Subround(F, e1, a1, b1, c1, d1, X[11], 15, k0);
    Subround(F, d1, e1, a1, b1, c1, X[12], 6, k0);
    Subround(F, c1, d1, e1, a1, b1, X[13], 7, k0);
    Subround(F, b1, c1, d1, e1, a1, X[14], 9, k0);
    Subround(F, a1, b1, c1, d1, e1, X[15], 8, k0);

    Subround(G, e1, a1, b1, c1, d1, X[7], 7, k1);
    Subround(G, d1, e1, a1, b1, c1, X[4], 6, k1);
    Subround(G, c1, d1, e1, a1, b1, X[13], 8, k1);
    Subround(G, b1, c1, d1, e1, a1, X[1], 13, k1);
    Subround(G, a1, b1, c1, d1, e1, X[10], 11, k1);
    Subround(G, e1, a1, b1, c1, d1, X[6], 9, k1);
    Subround(G, d1, e1, a1, b1, c1, X[15], 7, k1);
    Subround(G, c1, d1, e1, a1, b1, X[3], 15, k1);
    Subround(G, b1, c1, d1, e1, a1, X[12], 7, k1);
    Subround(G, a1, b1, c1, d1, e1, X[0], 12, k1);
    Subround(G, e1, a1, b1, c1, d1, X[9], 15, k1);
    Subround(G, d1, e1, a1, b1, c1, X[5], 9, k1);
    Subround(G, c1, d1, e1, a1, b1, X[2], 11, k1);
    Subround(G, b1, c1, d1, e1, a1, X[14], 7, k1);
    Subround(G, a1, b1, c1, d1, e1, X[11], 13, k1);
    Subround(G, e1, a1, b1, c1, d1, X[8], 12, k1);

    Subround(H, d1, e1, a1, b1, c1, X[3], 11, k2);
    Subround(H, c1, d1, e1, a1, b1, X[10], 13, k2);
    Subround(H, b1, c1, d1, e1, a1, X[14], 6, k2);
    Subround(H, a1, b1, c1, d1, e1, X[4], 7, k2);
    Subround(H, e1, a1, b1, c1, d1, X[9], 14, k2);
    Subround(H, d1, e1, a1, b1, c1, X[15], 9, k2);
    Subround(H, c1, d1, e1, a1, b1, X[8], 13, k2);
    Subround(H, b1, c1, d1, e1, a1, X[1], 15, k2);
    Subround(H, a1, b1, c1, d1, e1, X[2], 14, k2);
    Subround(H, e1, a1, b1, c1, d1, X[7], 8, k2);
    Subround(H, d1, e1, a1, b1, c1, X[0], 13, k2);
    Subround(H, c1, d1, e1, a1, b1, X[6], 6, k2);
    Subround(H, b1, c1, d1, e1, a1, X[13], 5, k2);
    Subround(H, a1, b1, c1, d1, e1, X[11], 12, k2);
    Subround(H, e1, a1, b1, c1, d1, X[5], 7, k2);
    Subround(H, d1, e1, a1, b1, c1, X[12], 5, k2);

    Subround(I, c1, d1, e1, a1, b1, X[1], 11, k3);
    Subround(I, b1, c1, d1, e1, a1, X[9], 12, k3);
    Subround(I, a1, b1, c1, d1, e1, X[11], 14, k3);
    Subround(I, e1, a1, b1, c1, d1, X[10], 15, k3);
    Subround(I, d1, e1, a1, b1, c1, X[0], 14, k3);
    Subround(I, c1, d1, e1, a1, b1, X[8], 15, k3);
    Subround(I, b1, c1, d1, e1, a1, X[12], 9, k3);
    Subround(I, a1, b1, c1, d1, e1, X[4], 8, k3);
    Subround(I, e1, a1, b1, c1, d1, X[13], 9, k3);
    Subround(I, d1, e1, a1, b1, c1, X[3], 14, k3);
    Subround(I, c1, d1, e1, a1, b1, X[7], 5, k3);
    Subround(I, b1, c1, d1, e1, a1, X[15], 6, k3);
    Subround(I, a1, b1, c1, d1, e1, X[14], 8, k3);
    Subround(I, e1, a1, b1, c1, d1, X[5], 6, k3);
    Subround(I, d1, e1, a1, b1, c1, X[6], 5, k3);
    Subround(I, c1, d1, e1, a1, b1, X[2], 12, k3);

    Subround(J, b1, c1, d1, e1, a1, X[4], 9, k4);
    Subround(J, a1, b1, c1, d1, e1, X[0], 15, k4);
    Subround(J, e1, a1, b1, c1, d1, X[5], 5, k4);
    Subround(J, d1, e1, a1, b1, c1, X[9], 11, k4);
    Subround(J, c1, d1, e1, a1, b1, X[7], 6, k4);
    Subround(J, b1, c1, d1, e1, a1, X[12], 8, k4);
    Subround(J, a1, b1, c1, d1, e1, X[2], 13, k4);
    Subround(J, e1, a1, b1, c1, d1, X[10], 12, k4);
    Subround(J, d1, e1, a1, b1, c1, X[14], 5, k4);
    Subround(J, c1, d1, e1, a1, b1, X[1], 12, k4);
    Subround(J, b1, c1, d1, e1, a1, X[3], 13, k4);
    Subround(J, a1, b1, c1, d1, e1, X[8], 14, k4);
    Subround(J, e1, a1, b1, c1, d1, X[11], 11, k4);
    Subround(J, d1, e1, a1, b1, c1, X[6], 8, k4);
    Subround(J, c1, d1, e1, a1, b1, X[15], 5, k4);
    Subround(J, b1, c1, d1, e1, a1, X[13], 6, k4);

    Subround(J, a2, b2, c2, d2, e2, X[5], 8, k5);
    Subround(J, e2, a2, b2, c2, d2, X[14], 9, k5);
    Subround(J, d2, e2, a2, b2, c2, X[7], 9, k5);
    Subround(J, c2, d2, e2, a2, b2, X[0], 11, k5);
    Subround(J, b2, c2, d2, e2, a2, X[9], 13, k5);
    Subround(J, a2, b2, c2, d2, e2, X[2], 15, k5);
    Subround(J, e2, a2, b2, c2, d2, X[11], 15, k5);
    Subround(J, d2, e2, a2, b2, c2, X[4], 5, k5);
    Subround(J, c2, d2, e2, a2, b2, X[13], 7, k5);
    Subround(J, b2, c2, d2, e2, a2, X[6], 7, k5);
    Subround(J, a2, b2, c2, d2, e2, X[15], 8, k5);
    Subround(J, e2, a2, b2, c2, d2, X[8], 11, k5);
    Subround(J, d2, e2, a2, b2, c2, X[1], 14, k5);
    Subround(J, c2, d2, e2, a2, b2, X[10], 14, k5);
    Subround(J, b2, c2, d2, e2, a2, X[3], 12, k5);
    Subround(J, a2, b2, c2, d2, e2, X[12], 6, k5);

    Subround(I, e2, a2, b2, c2, d2, X[6], 9, k6);
    Subround(I, d2, e2, a2, b2, c2, X[11], 13, k6);
    Subround(I, c2, d2, e2, a2, b2, X[3], 15, k6);
    Subround(I, b2, c2, d2, e2, a2, X[7], 7, k6);
    Subround(I, a2, b2, c2, d2, e2, X[0], 12, k6);
    Subround(I, e2, a2, b2, c2, d2, X[13], 8, k6);
    Subround(I, d2, e2, a2, b2, c2, X[5], 9, k6);
    Subround(I, c2, d2, e2, a2, b2, X[10], 11, k6);
    Subround(I, b2, c2, d2, e2, a2, X[14], 7, k6);
    Subround(I, a2, b2, c2, d2, e2, X[15], 7, k6);
    Subround(I, e2, a2, b2, c2, d2, X[8], 12, k6);
    Subround(I, d2, e2, a2, b2, c2, X[12], 7, k6);
    Subround(I, c2, d2, e2, a2, b2, X[4], 6, k6);
    Subround(I, b2, c2, d2, e2, a2, X[9], 15, k6);
    Subround(I, a2, b2, c2, d2, e2, X[1], 13, k6);
    Subround(I, e2, a2, b2, c2, d2, X[2], 11, k6);

    Subround(H, d2, e2, a2, b2, c2, X[15], 9, k7);
    Subround(H, c2, d2, e2, a2, b2, X[5], 7, k7);
    Subround(H, b2, c2, d2, e2, a2, X[1], 15, k7);
    Subround(H, a2, b2, c2, d2, e2, X[3], 11, k7);
    Subround(H, e2, a2, b2, c2, d2, X[7], 8, k7);
    Subround(H, d2, e2, a2, b2, c2, X[14], 6, k7);
    Subround(H, c2, d2, e2, a2, b2, X[6], 6, k7);
    Subround(H, b2, c2, d2, e2, a2, X[9], 14, k7);
    Subround(H, a2, b2, c2, d2, e2, X[11], 12, k7);
    Subround(H, e2, a2, b2, c2, d2, X[8], 13, k7);
    Subround(H, d2, e2, a2, b2, c2, X[12], 5, k7);
    Subround(H, c2, d2, e2, a2, b2, X[2], 14, k7);
    Subround(H, b2, c2, d2, e2, a2, X[10], 13, k7);
    Subround(H, a2, b2, c2, d2, e2, X[0], 13, k7);
    Subround(H, e2, a2, b2, c2, d2, X[4], 7, k7);
    Subround(H, d2, e2, a2, b2, c2, X[13], 5, k7);

    Subround(G, c2, d2, e2, a2, b2, X[8], 15, k8);
    Subround(G, b2, c2, d2, e2, a2, X[6], 5, k8);
    Subround(G, a2, b2, c2, d2, e2, X[4], 8, k8);
    Subround(G, e2, a2, b2, c2, d2, X[1], 11, k8);
    Subround(G, d2, e2, a2, b2, c2, X[3], 14, k8);
    Subround(G, c2, d2, e2, a2, b2, X[11], 14, k8);
    Subround(G, b2, c2, d2, e2, a2, X[15], 6, k8);
    Subround(G, a2, b2, c2, d2, e2, X[0], 14, k8);
    Subround(G, e2, a2, b2, c2, d2, X[5], 6, k8);
    Subround(G, d2, e2, a2, b2, c2, X[12], 9, k8);
    Subround(G, c2, d2, e2, a2, b2, X[2], 12, k8);
    Subround(G, b2, c2, d2, e2, a2, X[13], 9, k8);
    Subround(G, a2, b2, c2, d2, e2, X[9], 12, k8);
    Subround(G, e2, a2, b2, c2, d2, X[7], 5, k8);
    Subround(G, d2, e2, a2, b2, c2, X[10], 15, k8);
    Subround(G, c2, d2, e2, a2, b2, X[14], 8, k8);

    Subround(F, b2, c2, d2, e2, a2, X[12], 8, k9);
    Subround(F, a2, b2, c2, d2, e2, X[15], 5, k9);
    Subround(F, e2, a2, b2, c2, d2, X[10], 12, k9);
    Subround(F, d2, e2, a2, b2, c2, X[4], 9, k9);
    Subround(F, c2, d2, e2, a2, b2, X[1], 12, k9);
    Subround(F, b2, c2, d2, e2, a2, X[5], 5, k9);
    Subround(F, a2, b2, c2, d2, e2, X[8], 14, k9);
    Subround(F, e2, a2, b2, c2, d2, X[7], 6, k9);
    Subround(F, d2, e2, a2, b2, c2, X[6], 8, k9);
    Subround(F, c2, d2, e2, a2, b2, X[2], 13, k9);
    Subround(F, b2, c2, d2, e2, a2, X[13], 6, k9);
    Subround(F, a2, b2, c2, d2, e2, X[14], 5, k9);
    Subround(F, e2, a2, b2, c2, d2, X[0], 15, k9);
    Subround(F, d2, e2, a2, b2, c2, X[3], 13, k9);
    Subround(F, c2, d2, e2, a2, b2, X[9], 11, k9);
    Subround(F, b2, c2, d2, e2, a2, X[11], 11, k9);

    c1 = digest[1] + c1 + d2;
    digest[1] = digest[2] + d1 + e2;
    digest[2] = digest[3] + e1 + a2;
    digest[3] = digest[4] + a1 + b2;
    digest[4] = digest[0] + b1 + c2;
    digest[0] = c1;
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
        out[i + 3] = buf[i >> 2] >> 24;
    }
}
