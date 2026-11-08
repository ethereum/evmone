// The C CIOS almost Montgomery multiplication of modexp.cpp (dynamic extent), for reference.
#include "amm.hpp"
#include <evmone_precompiles/mulmod.hpp>

namespace amm
{
void ref_amm(uint64_t* rp, const uint64_t* xp, const uint64_t* yp, const uint64_t* mp,
    uint64_t mod_inv, size_t n) noexcept
{
    using namespace evmone::crypto;
    const std::span<uint64_t> r{rp, n};
    const std::span<const uint64_t> x{xp, n};
    const std::span<const uint64_t> y{yp, n};
    const std::span<const uint64_t> mod{mp, n};
    INTX_REQUIRE(n > 0);
    INTX_REQUIRE(x.size() == n);
    INTX_REQUIRE(mod.size() == n);
    INTX_REQUIRE(mod.back() != 0);
    INTX_REQUIRE(mod[0] * mod_inv + 1 == 0);
    INTX_REQUIRE(r.data() != x.data() && r.data() != y.data());

    const auto r_lo = r.subspan(0, n - 1);
    const auto r_hi = r.subspan(1);
    const auto mod_hi = mod.subspan(1);

    bool r_carry = false;
    {
        const auto c1 = evmone::crypto::mul(r, x, y[0]);
        const auto m = r[0] * mod_inv;
        const auto p = intx::umul(mod[0], m) + r[0];
        const auto c3 = addmul(r_lo, r_hi, mod_hi, m, p[1]);
        std::tie(r[n - 1], r_carry) = intx::addc(c1, c3);
    }
    for (size_t i = 1; i != n; ++i)
    {
        const auto c1 = addmul(r, r, x, y[i]);
        const auto m = r[0] * mod_inv;
        const auto p = intx::umul(mod[0], m) + r[0];
        const auto c3 = addmul(r_lo, r_hi, mod_hi, m, p[1]);
        std::tie(r[n - 1], r_carry) = intx::addc(c1, c3, r_carry);
    }
    if (r_carry)
        sub(r, mod);
}
}  // namespace amm
