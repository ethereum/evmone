// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include <evmmax/evmmax.hpp>
#include <gtest/gtest.h>
#include <array>

using namespace intx;
using namespace evmmax;
using evmone::test::evm;

// TODO(intx): Add ""_u384.
inline constexpr auto operator""_u384(const char* s)
{
    return intx::from_string<intx::uint384>(s);
}

constexpr auto P23 = 23_u256;
constexpr auto BN254Mod = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_u256;
constexpr auto Secp256k1Mod =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;
constexpr auto M256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256;
constexpr auto BLS12384Mod =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab_u384;


template <typename UintT, const UintT& Mod>
struct ModA : ModArith<UintT>
{
    using uint = UintT;
    ModA() : ModArith<UintT>{Mod} {}
};

template <typename>
class evmmax_test : public testing::Test
{};

using test_types = testing::Types<ModA<uint256, P23>, ModA<uint256, BN254Mod>,
    ModA<uint256, Secp256k1Mod>, ModA<uint256, M256>, ModA<uint384, BLS12384Mod>>;
TYPED_TEST_SUITE(evmmax_test, test_types, testing::internal::DefaultNameGenerator);

TYPED_TEST(evmmax_test, to_from_mont)
{
    const typename TypeParam::uint v = 1;

    const TypeParam s;
    const auto x = s.to_mont(v);
    EXPECT_EQ(s.from_mont(x), v);
}

TYPED_TEST(evmmax_test, to_from_mont_0)
{
    const TypeParam s;
    EXPECT_EQ(s.to_mont(0), 0);
    EXPECT_EQ(s.from_mont(0), 0);
}

template <typename Mod>
static auto get_test_values(const Mod& m) noexcept
{
    using Uint = typename Mod::uint;
    return std::array{
        m.mod - 1,
        m.mod - 2,
        m.mod / 2 + 1,
        m.mod / 2,
        m.mod / 2 - 1,
        Uint{2},
        Uint{1},
        Uint{0},
    };
}

TYPED_TEST(evmmax_test, add)
{
    const TypeParam m;
    const auto values = get_test_values(m);

    for (const auto& x : values)
    {
        const auto xm = m.to_mont(x);
        for (const auto& y : values)
        {
            const auto expected =
                udivrem(intx::uint<TypeParam::uint::num_bits + 64>{x} + y, m.mod).rem;

            const auto ym = m.to_mont(y);
            const auto s1m = m.add(xm, ym);
            const auto s1 = m.from_mont(s1m);
            EXPECT_EQ(s1, expected);

            // Conversion to Montgomery form is not necessary for addition to work.
            const auto s2 = m.add(x, y);
            EXPECT_EQ(s2, expected);
        }
    }
}

TYPED_TEST(evmmax_test, sub)
{
    const TypeParam m;
    const auto values = get_test_values(m);

    for (const auto& x : values)
    {
        const auto xm = m.to_mont(x);
        for (const auto& y : values)
        {
            const auto expected =
                udivrem(intx::uint<TypeParam::uint::num_bits + 64>{x} + m.mod - y, m.mod).rem;

            const auto ym = m.to_mont(y);
            const auto d1m = m.sub(xm, ym);
            const auto d1 = m.from_mont(d1m);
            EXPECT_EQ(d1, expected);

            // Conversion to Montgomery form is not necessary for subtraction to work.
            const auto d2 = m.sub(x, y);
            EXPECT_EQ(d2, expected);
        }
    }
}

TYPED_TEST(evmmax_test, mul)
{
    const TypeParam m;
    const auto values = get_test_values(m);

    for (const auto& x : values)
    {
        const auto xm = m.to_mont(x);
        for (const auto& y : values)
        {
            const auto expected = udivrem(umul(x, y), m.mod).rem;

            const auto ym = m.to_mont(y);
            const auto pm = m.mul(xm, ym);
            const auto p = m.from_mont(pm);
            EXPECT_EQ(p, expected);
        }
    }
}

namespace
{
template <typename UintT>
inline bytecode create_test_bytecode()
{
    constexpr auto size = sizeof(UintT);
    return calldatacopy(push(0), push(0), push(size * 3)) + setupx(3, size, 0, 1) +
           storex(2, size, 0) + mulmodx(2, 1, 0) + loadx(1, 2, size * 3) + ret(size * 3, size);
}

}  // namespace

TEST_P(evm, exec_bn254_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    const ModA<uint256, BN254Mod> m;

    uint8_t calldata[3 * sizeof(uint256)];
    intx::be::unsafe::store(&calldata[0], BN254Mod);

    const auto values = get_test_values(m);

    const auto code = create_test_bytecode<uint256>();

    for (const auto& x : values)
    {
        for (const auto& y : values)
        {
            const auto expected = udivrem(umul(x, y), m.mod).rem;

            intx::be::unsafe::store(&calldata[32], x);
            intx::be::unsafe::store(&calldata[64], y);

            execute(1000, code, {calldata, 96});
            EXPECT_EQ(result.status_code, EVMC_SUCCESS);
            EXPECT_OUTPUT_INT(expected);
        }
    }
}

TEST_P(evm, exec_bls_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    const ModA<uint384, BLS12384Mod> m;

    constexpr auto size = sizeof(uint384);
    uint8_t calldata[3 * size];
    intx::be::unsafe::store(&calldata[0], BLS12384Mod);

    const auto values = get_test_values(m);

    const auto code = create_test_bytecode<uint384>();

    for (const auto& x : values)
    {
        for (const auto& y : values)
        {
            const auto expected = udivrem(umul(x, y), m.mod).rem;

            intx::be::unsafe::store(&calldata[size], x);
            intx::be::unsafe::store(&calldata[size * 2], y);

            execute(1000, code, {calldata, size * 3});
            EXPECT_EQ(result.status_code, EVMC_SUCCESS);
            ASSERT_EQ(result.output_size, size);
            EXPECT_EQ(intx::be::unsafe::load<uint384>(result.output_data), expected);
        }
    }
}

TEST_P(evm, exec_invalid_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    {
        // Even modulus
        constexpr auto size = sizeof(uint256);
        uint8_t calldata[3 * size];

        const auto code = create_test_bytecode<uint256>();
        intx::be::unsafe::store(&calldata[0], BN254Mod + 1);
        execute(1000, code, {calldata, size * 3});
        EXPECT_EQ(result.status_code, EVMC_FAILURE);
    }

    {
        // Modulus too big
        constexpr auto size = sizeof(intx::uint<4160>);
        uint8_t calldata[3 * size];

        const auto code = create_test_bytecode<intx::uint<4160>>();
        intx::be::unsafe::store(&calldata[0], intx::uint<4160>(7));
        execute(1000, code, {calldata, size * 3});
        EXPECT_EQ(result.status_code, EVMC_FAILURE);
    }

    {
        // Too many value slots
        constexpr auto size = sizeof(uint256);
        uint8_t calldata[size];

        const auto code = calldatacopy(push(0), push(0), push(size)) + setupx(257, size, 0, 1);
        intx::be::unsafe::store(&calldata[0], BN254Mod);
        execute(1000, code, {calldata, size});
        EXPECT_EQ(result.status_code, EVMC_FAILURE);
    }

    {
        // not enough gas
        constexpr auto size = sizeof(uint256);
        uint8_t calldata[3 * size];

        const auto code = create_test_bytecode<uint256>();
        intx::be::unsafe::store(&calldata[0], BN254Mod);
        execute(45, code, {calldata, size * 3});
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    }

    {
        // Too much evmmax memory used
        constexpr auto size = sizeof(intx::uint<2048>);
        uint8_t calldata[size * 3];

        const auto code = calldatacopy(push(0), push(0), push(size)) + setupx(1, size, 0, 1) +
                          setupx(256, size, 0, 2);
        intx::be::unsafe::store(&calldata[0], intx::uint<2048>(BN254Mod));
        execute(1000, code, {calldata, size});
        EXPECT_EQ(result.status_code, EVMC_FAILURE);
    }

    {
        // No active modulus
        execute(1000, addmodx(0, 0, 1));
        EXPECT_EQ(result.status_code, EVMC_FAILURE);

        execute(1000, mulmodx(0, 0, 2));
        EXPECT_EQ(result.status_code, EVMC_FAILURE);

        execute(1000, submodx(0, 0, 2));
        EXPECT_EQ(result.status_code, EVMC_FAILURE);

        execute(1000, loadx(1, 0, 0));
        EXPECT_EQ(result.status_code, EVMC_FAILURE);

        execute(1000, storex(1, 0, 0));
        EXPECT_EQ(result.status_code, EVMC_FAILURE);
    }
}
