#include "modexp.hpp"
#include <evmmax/evmmax.hpp>

#include <bit>

using namespace intx;

namespace
{
template <typename UIntT>
UIntT modexp_odd(const UIntT& base, const evmc::bytes_view& exp, const UIntT& mod)
{
    const evmmax::ModArith<UIntT> arith(mod);

    UIntT ret = arith.to_mont(UIntT{1});
    const auto base_mont = arith.to_mont(base);

    for (auto e : exp)
    {
        unsigned char mask = 0x80;
        while (mask != 0)
        {
            ret = arith.mul(ret, ret);
            if ((mask & e) != 0)
                ret = arith.mul(ret, base_mont);

            mask >>= 1;
        }
    }

    return arith.from_mont(ret);
}

template <typename UIntT>
UIntT modexp_pow_of_two(const UIntT& base, const evmc::bytes_view& exp, const UIntT& mod)
{
    const auto nlz = clz(mod);

    const UIntT mod_mask = std::numeric_limits<UIntT>::max() >> (nlz + 1);
    UIntT ret = UIntT{1};
    for (auto e : exp)
    {
        unsigned char mask = 0x80;
        while (mask != 0)
        {
            ret = ret * ret;
            ret &= mod_mask;
            if ((mask & e) != 0)
            {
                ret = ret * base;
                ret &= mod_mask;
            }

            mask >>= 1;
        }
    }

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
UIntT modexp_impl(const UIntT& base, const evmc::bytes_view& exp, const UIntT& mod)
{
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
UIntT load_from_bytes(const evmc::bytes_view& data)
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
bool modexp(uint8_t* output, size_t output_size, const evmc::bytes_view& base,
    const evmc::bytes_view& exp, const evmc::bytes_view& mod)
{
    constexpr auto MAX_INPUT_SIZE = 1024;
    if (base.size() > MAX_INPUT_SIZE || exp.size() > MAX_INPUT_SIZE || mod.size() > MAX_INPUT_SIZE)
        return false;

    // mod is zero
    if (mod.find_first_not_of(uint8_t{0}) == std::string::npos)
    {
        memset(output, 0, output_size);
        return true;
    }

    const auto size = std::max(mod.size(), base.size());

    assert(output_size >= mod.size());

    evmc::bytes res_bytes;
    if (size <= 32)
    {
        res_bytes.resize(32);
        intx::be::unsafe::store(res_bytes.data(),
            modexp_impl(load_from_bytes<uint256>(base), exp, load_from_bytes<uint256>(mod)));
    }
    else if (size <= 64)
    {
        res_bytes.resize(64);
        intx::be::unsafe::store(res_bytes.data(),
            modexp_impl(load_from_bytes<uint512>(base), exp, load_from_bytes<uint512>(mod)));
    }
    else if (size <= 128)
    {
        res_bytes.resize(128);
        intx::be::unsafe::store(
            res_bytes.data(), modexp_impl(load_from_bytes<intx::uint<1024>>(base), exp,
                                  load_from_bytes<intx::uint<1024>>(mod)));
    }
    else if (size <= 256)
    {
        res_bytes.resize(256);
        intx::be::unsafe::store(
            res_bytes.data(), modexp_impl(load_from_bytes<intx::uint<2048>>(base), exp,
                                  load_from_bytes<intx::uint<2048>>(mod)));
    }
    else
    {
        assert(output_size <= 1024);
        res_bytes.resize(1024);
        intx::be::unsafe::store(
            res_bytes.data(), modexp_impl(load_from_bytes<intx::uint<8192>>(base), exp,
                                  load_from_bytes<intx::uint<8192>>(mod)));
    }

    memcpy(output, &res_bytes[res_bytes.size() - output_size], output_size);
    return true;
}


}  // namespace evmone::crypto
