#include "modexp.hpp"
#include <evmmax/evmmax.hpp>
#include <bit>
#include <span>

using namespace intx;

namespace
{
template <unsigned N>
void trunc(std::span<uint8_t> dst, const intx::uint<N>& x) noexcept
{
    assert(dst.size() <= N / 8);  // destination must be smaller than the source value
    const auto d = to_big_endian(x);
    std::copy_n(&as_bytes(d)[sizeof(d) - dst.size()], dst.size(), dst.begin());
}

template <typename UIntT>
UIntT modexp_odd(const UIntT& base, evmc::bytes_view exp, const UIntT& mod)
{
    const evmmax::ModArith<UIntT> arith(mod);

    UIntT ret = arith.to_mont(UIntT{1});
    const auto base_mont = arith.to_mont(base);
    // const auto base2 = arith.mul(base_mont, base_mont);
    // const auto base3 = arith.mul(base_mont, base2);

    for (const auto e : exp)
    {
        for (size_t i = 8; i != 0; --i)
        {
            ret = arith.mul(ret, ret);
            const auto bit = e >> (i - 1) & 1;
            if (bit != 0)
                ret = arith.mul(ret, base_mont);
        }
    }

    return arith.from_mont(ret);
}

template <typename UIntT>
UIntT modexp_pow_of_two(const UIntT& base, evmc::bytes_view exp, const UIntT& mod)
{
    // FIXME: It should compute the value correctly for mod == 1, just checking if covered by tests.
    assert(mod != 1);
    UIntT ret = 1;
    for (auto e : exp)
    {
        unsigned char mask = 0x80;
        while (mask != 0)
        {
            ret *= ret;
            if ((mask & e) != 0)
                ret *= base;
            mask >>= 1;
        }
    }

    const auto mod_mask = mod - 1;
    ret &= mod_mask;
    return ret;
}

template <typename UIntT>
size_t ctz(const UIntT& value)
{
    size_t mod_tailing_zeros = 0;
    for (size_t i = 0; i < value.num_words; ++i)
    {
        if (value[i] == 0)
        {
            mod_tailing_zeros += value.word_num_bits;
            continue;
        }
        else
        {
            mod_tailing_zeros += static_cast<size_t>(std::countr_zero(value[i]));
            break;
        }
    }

    return mod_tailing_zeros;
}

template <typename UIntT>
UIntT modinv_2k(const UIntT& x, size_t k)
{
    UIntT b{1};
    UIntT res;
    for (size_t i = 0; i < k; ++i)
    {
        UIntT t = b & UIntT{1};
        b = (b - x * t) >> 1;
        res += t << i;
    }

    return res;
}

template <typename UIntT>
UIntT modexp_impl(const UIntT& base, evmc::bytes_view exp, const UIntT& mod)
{
    // FIXME: We should strip leading 0 bits/bytes of exp. The gas cost model requires it.

    // is odd
    if ((mod & UIntT{1}) == UIntT{1})
    {
        return modexp_odd(base, exp, mod);
    }
    else if ((mod << (clz(mod) + 1)) == 0)  // is power of 2
    {
        return modexp_pow_of_two(base, exp, mod);
    }
    else  // is even
    {
        const auto mod_tailing_zeros = ctz(mod);

        auto const N = mod >> mod_tailing_zeros;
        const UIntT K = UIntT{1} << mod_tailing_zeros;

        const auto x1 = modexp_odd(base, exp, N);
        const auto x2 = modexp_pow_of_two(base, exp, K);

        const auto N_inv = modinv_2k(N, mod_tailing_zeros);

        return x1 + (((x2 - x1) * N_inv) % K) * N;
    }
}

template <typename UIntT>
UIntT load_from_bytes(evmc::bytes_view data)
{
    constexpr auto num_bytes = UIntT::num_words * sizeof(typename UIntT::word_type);
    assert(data.size() <= num_bytes);
    if (data.size() == num_bytes)
    {
        return intx::be::unsafe::load<UIntT>(data.data());
    }
    else
    {
        evmc::bytes tmp;
        tmp.resize(num_bytes);
        std::memcpy(&tmp[num_bytes - data.size()], data.data(), data.size());
        return intx::be::unsafe::load<UIntT>(tmp.data());
    }
}

}  // namespace

namespace evmone::crypto
{
bool modexp(evmc::bytes_view base, evmc::bytes_view exp, evmc::bytes_view mod, uint8_t* output)
{
    static constexpr auto MAX_INPUT_SIZE = 1024;
    if (base.size() > MAX_INPUT_SIZE || exp.size() > MAX_INPUT_SIZE || mod.size() > MAX_INPUT_SIZE)
        return false;

    const auto size = std::max(mod.size(), base.size());

    intx::uint<MAX_INPUT_SIZE * 8> max_res;
    if (size <= 32)
    {
        max_res = modexp_impl(load_from_bytes<uint256>(base), exp, load_from_bytes<uint256>(mod));
    }
    else if (size <= 64)
    {
        max_res = modexp_impl(load_from_bytes<uint512>(base), exp, load_from_bytes<uint512>(mod));
    }
    else if (size <= 128)
    {
        max_res = modexp_impl(
            load_from_bytes<intx::uint<1024>>(base), exp, load_from_bytes<intx::uint<1024>>(mod));
    }
    else if (size <= 256)
    {
        max_res = modexp_impl(
            load_from_bytes<intx::uint<2048>>(base), exp, load_from_bytes<intx::uint<2048>>(mod));
    }
    else
    {
        max_res = modexp_impl(load_from_bytes<intx::uint<MAX_INPUT_SIZE * 8>>(base), exp,
            load_from_bytes<intx::uint<MAX_INPUT_SIZE * 8>>(mod));
    }

    trunc(std::span{output, mod.size()}, max_res);
    return true;
}


}  // namespace evmone::crypto
