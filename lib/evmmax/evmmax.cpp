// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmmax/evmmax.hpp>

using namespace intx;

namespace evmmax
{
struct EXMMAXModStateInterface
{
    virtual void loadx(uint8_t* out_ptr, size_t val_idx, size_t num_vals) const noexcept = 0;
    virtual void storex(const uint8_t* in_ptr, size_t dst_val_idx, size_t num_vals) noexcept = 0;
    virtual void addmodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept = 0;
    virtual void submodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept = 0;
    virtual void mulmodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept = 0;

    [[nodiscard]] virtual size_t value_size_multiplier() const noexcept = 0;
    [[nodiscard]] virtual int64_t addmodx_gas_cost() const noexcept = 0;
    [[nodiscard]] virtual int64_t mulmodx_gas_cost() const noexcept = 0;
    [[nodiscard]] virtual size_t num_values() const noexcept = 0;

    virtual ~EXMMAXModStateInterface() noexcept = default;
};

namespace
{
/// Copy of intx::be::unsafe::load but with additional src size parameter
template <typename IntT>
inline IntT load(const uint8_t* src, size_t src_size) noexcept
{
    // Align bytes.
    // TODO: Using memcpy() directly triggers this optimization bug in GCC:
    //   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=107837
    alignas(IntT) std::byte aligned_storage[sizeof(IntT)] = {};
    std::memcpy(&aligned_storage[sizeof(IntT) - src_size], src, src_size);
    // TODO(C++23): Use std::start_lifetime_as<uint256>().
    return to_big_endian(*reinterpret_cast<const IntT*>(&aligned_storage));
}

template <typename T>
inline void store(uint8_t* dst, const T& x, size_t dst_size) noexcept
{
    const auto d = to_big_endian(x);
    std::memcpy(dst, &reinterpret_cast<const std::byte*>(&d)[sizeof(T) - dst_size], dst_size);
}

inline constexpr int64_t compute_addmodx_cost(size_t value_size_mult) noexcept
{
    constexpr int64_t ADDMODX_GAS_A = 20;
    constexpr int64_t ADDMODX_GAS_B = 15;

    return (ADDMODX_GAS_A * static_cast<int64_t>(value_size_mult) + ADDMODX_GAS_B + 49) / 100;
}

inline constexpr int64_t compute_mulmodx_cost(size_t value_size_mult) noexcept
{
    constexpr int64_t MULMODX_LO_GAS_A = 9;
    constexpr int64_t MULMODX_LO_GAS_B = 0;
    constexpr int64_t MULMODX_LO_GAS_C = 24;

    return (MULMODX_LO_GAS_A * static_cast<int64_t>(value_size_mult * value_size_mult) +
               MULMODX_LO_GAS_B * static_cast<int64_t>(value_size_mult) + MULMODX_LO_GAS_C + 99) /
           100;
}

template <typename UintT>
struct EXMMAXModState : public EXMMAXModStateInterface
{
    std::vector<UintT> values;
    const ModArith<UintT> arith;
    const size_t value_size_mult;
    const int64_t addmodx_cost;
    const int64_t mulmodx_cost;

    explicit EXMMAXModState(const UintT& mod, size_t mod_size, size_t vals_used) noexcept
      : arith(mod),
        value_size_mult((mod_size + 7) / 8),
        addmodx_cost(compute_addmodx_cost(value_size_mult)),
        mulmodx_cost(compute_mulmodx_cost(value_size_mult))
    {
        values.resize(vals_used);
    }

    void loadx(uint8_t* out_ptr, size_t val_idx, size_t num_vals) const noexcept override
    {
        assert(val_idx + num_vals <= values.size());

        for (unsigned i = 0; i < num_vals; ++i)
        {
            store(out_ptr + i * value_size_mult * 8, arith.from_mont(values[val_idx + i]),
                value_size_mult * 8);
        }
    }

    void storex(const uint8_t* in_ptr, size_t dst_val_idx, size_t num_vals) noexcept override
    {
        assert(dst_val_idx + num_vals <= values.size());

        for (unsigned i = 0; i < num_vals; ++i)
        {
            values[dst_val_idx + i] =
                arith.to_mont(load<UintT>(in_ptr + value_size_mult * 8 * i, value_size_mult * 8));
        }
    }

    void addmodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept override
    {
        assert(dst_idx < values.size() && x_idx < values.size() && y_idx < values.size());

        values[dst_idx] = arith.add(values[x_idx], values[y_idx]);
    }

    void submodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept override
    {
        assert(dst_idx < values.size() && x_idx < values.size() && y_idx < values.size());

        values[dst_idx] = arith.sub(values[x_idx], values[y_idx]);
    }

    void mulmodx(size_t dst_idx, size_t x_idx, size_t y_idx) noexcept override
    {
        assert(dst_idx < values.size() && x_idx < values.size() && y_idx < values.size());

        values[dst_idx] = arith.mul(values[x_idx], values[y_idx]);
    }

    [[nodiscard]] size_t num_values() const noexcept override { return values.size(); }
    [[nodiscard]] size_t value_size_multiplier() const noexcept override { return value_size_mult; }
    [[nodiscard]] int64_t addmodx_gas_cost() const noexcept override { return addmodx_cost; }
    [[nodiscard]] int64_t mulmodx_gas_cost() const noexcept override { return mulmodx_cost; }
};

[[nodiscard]] std::unique_ptr<EXMMAXModStateInterface> create_mod_state(
    const uint8_t* mod_ptr, size_t mod_size, size_t vals_used) noexcept
{
    // Must be odd.
    assert((mod_ptr[mod_size - 1] & 1) == 1);
    // Max mod size must be <= 4096 bits
    assert(mod_size <= 512);

    if (mod_size <= 16)
    {
        return std::make_unique<EXMMAXModState<intx::uint<128>>>(
            load<intx::uint<128>>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 24)
    {
        return std::make_unique<EXMMAXModState<intx::uint<192>>>(
            load<intx::uint<192>>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 32)
    {
        return std::make_unique<EXMMAXModState<uint256>>(
            load<uint256>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 40)
    {
        return std::make_unique<EXMMAXModState<uint320>>(
            load<uint320>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 48)
    {
        return std::make_unique<EXMMAXModState<uint384>>(
            load<uint384>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 56)
    {
        return std::make_unique<EXMMAXModState<intx::uint<448>>>(
            load<intx::uint<448>>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else if (mod_size <= 64)
    {
        return std::make_unique<EXMMAXModState<uint512>>(
            load<uint512>(mod_ptr, mod_size), mod_size, vals_used);
    }
    else
    {
        /// TODO: Implement for intermediate `mod_size` values up to 512 bytes
        return std::make_unique<EXMMAXModState<intx::uint<4096>>>(
            load<intx::uint<4096>>(mod_ptr, mod_size), mod_size, vals_used);
    }
}

[[nodiscard]] bool charge_gas_precompute_mont(int64_t& gas_left, size_t mod_size) noexcept
{
    // TODO: Set proper values for A and B
    static constexpr int64_t A = 1;
    static constexpr int64_t B = 5;

    const size_t val_size_multiplier = (mod_size + 7) / 8;

    if (val_size_multiplier < 50)
        gas_left -= A * static_cast<int64_t>(val_size_multiplier) + B;
    else
    {
        // TODO: Add support for subquadratic mulmont cost model
        assert(false);
        return false;
    }

    return gas_left >= 0;
}

}  // namespace

[[nodiscard]] bool EVMMAXState::exists(const intx::uint256& mod_id) const noexcept
{
    // TODO: Add support for uint256 to be a key in std::unordered_map
    const auto mod_id_bytes = intx::be::store<evmc::bytes32>(mod_id);

    return mods.contains(mod_id_bytes);
}

[[nodiscard]] evmc_status_code EVMMAXState::setupx(int64_t& gas_left, const uint256& mod_id,
    const uint8_t* mod_ptr, size_t mod_size, size_t vals_used) noexcept
{
    // TODO: Add support for uint256 to be a key in std::unordered_map
    const auto mod_id_bytes = intx::be::store<evmc::bytes32>(mod_id);

    if (active_mod != mods.end() && active_mod->first == mod_id_bytes)
        return EVMC_SUCCESS;

    active_mod = mods.find(mod_id_bytes);
    if (active_mod != mods.end())
        return EVMC_SUCCESS;

    if (!validate_memory_usage(mod_size, vals_used))
        return EVMC_FAILURE;

    if (!charge_gas_precompute_mont(gas_left, mod_size))
        return EVMC_OUT_OF_GAS;

    active_mod = mods.emplace(mod_id_bytes, create_mod_state(mod_ptr, mod_size, vals_used)).first;
    return EVMC_SUCCESS;
}

[[nodiscard]] evmc_status_code EVMMAXState::loadx(
    int64_t& gas_left, uint8_t* out_ptr, size_t val_idx, size_t num_vals) noexcept
{
    if (active_mod == mods.end())
        return EVMC_FAILURE;

    if ((gas_left -= active_mod->second->mulmodx_gas_cost() * static_cast<int64_t>(num_vals)) < 0)
        return EVMC_OUT_OF_GAS;

    active_mod->second->loadx(out_ptr, val_idx, num_vals);
    return EVMC_SUCCESS;
}

[[nodiscard]] evmc_status_code EVMMAXState::storex(
    int64_t& gas_left, const uint8_t* in_ptr, size_t dst_val_idx, size_t num_vals) noexcept
{
    if (active_mod == mods.end())
        return EVMC_FAILURE;

    if ((gas_left -= active_mod->second->mulmodx_gas_cost() * static_cast<int64_t>(num_vals)) < 0)
        return EVMC_OUT_OF_GAS;

    active_mod->second->storex(in_ptr, dst_val_idx, num_vals);
    return EVMC_SUCCESS;
}

[[nodiscard]] evmc_status_code EVMMAXState::addmodx(
    int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept
{
    if (active_mod == mods.end())
        return EVMC_FAILURE;

    if ((gas_left -= active_mod->second->addmodx_gas_cost()) < 0)
        return EVMC_OUT_OF_GAS;

    active_mod->second->addmodx(dst_idx, x_idx, y_idx);
    return EVMC_SUCCESS;
}

[[nodiscard]] evmc_status_code EVMMAXState::submodx(
    int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept
{
    if (active_mod == mods.end())
        return EVMC_FAILURE;

    if ((gas_left -= active_mod->second->addmodx_gas_cost()) < 0)
        return EVMC_OUT_OF_GAS;

    active_mod->second->submodx(dst_idx, x_idx, y_idx);
    return EVMC_SUCCESS;
}

[[nodiscard]] evmc_status_code EVMMAXState::mulmodx(
    int64_t& gas_left, size_t dst_idx, size_t x_idx, size_t y_idx) noexcept
{
    if (active_mod == mods.end())
        return EVMC_FAILURE;

    if ((gas_left -= active_mod->second->mulmodx_gas_cost()) < 0)
        return EVMC_OUT_OF_GAS;

    active_mod->second->mulmodx(dst_idx, x_idx, y_idx);
    return EVMC_SUCCESS;
}

[[nodiscard]] size_t EVMMAXState::active_mod_value_size_multiplier() const noexcept
{
    if (active_mod == mods.end())
        return 0;

    return active_mod->second->value_size_multiplier();
}

[[nodiscard]] bool EVMMAXState::validate_memory_usage(size_t val_size, size_t num_val) noexcept
{
    static constexpr auto EVMMAX_MAX_MEM_SIZE = 65536;

    size_t total_size = val_size * num_val;
    for (const auto& item : mods)
        total_size += item.second->num_values() * item.second->value_size_multiplier() * 8;

    return total_size <= EVMMAX_MAX_MEM_SIZE;
}

void EVMMAXState::clear() noexcept
{
    mods.clear();
    active_mod = mods.end();
}

EVMMAXState::EVMMAXState() noexcept = default;
EVMMAXState::~EVMMAXState() = default;

namespace
{
/// Compute the modulus inverse for Montgomery multiplication, i.e. N': mod⋅N' = 2⁶⁴-1.
///
/// @param mod0  The least significant word of the modulus.
inline constexpr uint64_t compute_mod_inv(uint64_t mod0) noexcept
{
    // TODO: Find what is this algorithm and why it works.
    uint64_t base = 0 - mod0;
    uint64_t result = 1;
    for (auto i = 0; i < 64; ++i)
    {
        result *= base;
        base *= base;
    }
    return result;
}

/// Compute R² % mod.
template <typename UintT>
inline UintT compute_r_squared(const UintT& mod) noexcept
{
    // R is 2^num_bits, R² is 2^(2*num_bits) and needs 2*num_bits+1 bits to represent,
    // rounded to 2*num_bits+64) for intx requirements.
    static constexpr auto r2 = intx::uint<UintT::num_bits * 2 + 64>{1} << (UintT::num_bits * 2);
    return intx::udivrem(r2, mod).rem;
}

inline constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    const auto p = umul(a, b) + t + c;
    return {p[1], p[0]};
}
}  // namespace

template <typename UintT>
ModArith<UintT>::ModArith(const UintT& modulus) noexcept
  : mod{modulus}, m_r_squared{compute_r_squared(modulus)}, m_mod_inv{compute_mod_inv(modulus[0])}
{}

template <typename UintT>
UintT ModArith<UintT>::mul(const UintT& x, const UintT& y) const noexcept
{
    // Coarsely Integrated Operand Scanning (CIOS) Method
    // Based on 2.3.2 from
    // High-Speed Algorithms & Architectures For Number-Theoretic Cryptosystems
    // https://www.microsoft.com/en-us/research/wp-content/uploads/1998/06/97Acar.pdf

    static constexpr auto S = UintT::num_words;

    intx::uint<UintT::num_bits + 64> t;
    for (size_t i = 0; i != S; ++i)
    {
        uint64_t c = 0;
        for (size_t j = 0; j != S; ++j)
            std::tie(c, t[j]) = addmul(t[j], x[j], y[i], c);
        auto tmp = addc(t[S], c);
        t[S] = tmp.value;
        auto d = tmp.carry;

        c = 0;
        auto m = t[0] * m_mod_inv;
        std::tie(c, t[0]) = addmul(t[0], m, mod[0], c);
        for (size_t j = 1; j != S; ++j)
            std::tie(c, t[j - 1]) = addmul(t[j], m, mod[j], c);
        tmp = addc(t[S], c);
        t[S - 1] = tmp.value;
        t[S] = d + tmp.carry;  // TODO: Carry is 0 for sparse modulus.
    }

    if (t >= mod)  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
        t -= mod;

    return static_cast<UintT>(t);
}

template <typename UintT>
UintT ModArith<UintT>::to_mont(const UintT& x) const noexcept
{
    return mul(x, m_r_squared);
}

template <typename UintT>
UintT ModArith<UintT>::from_mont(const UintT& x) const noexcept
{
    return mul(x, 1);
}

template <typename UintT>
UintT ModArith<UintT>::add(const UintT& x, const UintT& y) const noexcept
{
    const auto s = addc(x, y);  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
    const auto d = subc(s.value, mod);
    return (!s.carry && d.carry) ? s.value : d.value;
}

template <typename UintT>
UintT ModArith<UintT>::sub(const UintT& x, const UintT& y) const noexcept
{
    const auto d = subc(x, y);
    const auto s = d.value + mod;
    return (d.carry) ? s : d.value;
}

template class ModArith<uint256>;
template class ModArith<uint384>;
}  // namespace evmmax
