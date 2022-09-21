// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/hash_utils.hpp>
#include <test/state/rlp.hpp>
#include <test/utils/utils.hpp>
#include <bit>

using namespace evmone;
using namespace evmc::literals;
using namespace intx;

static constexpr auto emptyBytesHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

static constexpr auto emptyMPTHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

TEST(state_rlp, empty_bytes_hash)
{
    EXPECT_EQ(keccak256({}), emptyBytesHash);
}

TEST(state_rlp, empty_mpt_hash)
{
    const auto rlp_null = rlp::encode(0);
    EXPECT_EQ(rlp_null, bytes{0x80});
    EXPECT_EQ(keccak256(rlp_null), emptyMPTHash);
}

TEST(state_rlp, encode_string_short)
{
    EXPECT_EQ(rlp::encode(0x01), "01"_hex);
    EXPECT_EQ(rlp::encode(0x31), "31"_hex);
    EXPECT_EQ(rlp::encode(0x7f), "7f"_hex);
}

TEST(state_rlp, encode_string_long)
{
    const auto buffer = std::make_unique<uint8_t[]>(0xffffff);

    const auto r1 = rlp::encode({buffer.get(), 0xaabb});
    EXPECT_EQ(r1.size(), 0xaabb + 3);
    EXPECT_EQ(hex({r1.data(), 10}), "b9aabb00000000000000");

    const auto r2 = rlp::encode({buffer.get(), 0xffff});
    EXPECT_EQ(r2.size(), 0xffff + 3);
    EXPECT_EQ(hex({r2.data(), 10}), "b9ffff00000000000000");

    const auto r3 = rlp::encode({buffer.get(), 0xaabbcc});
    EXPECT_EQ(r3.size(), 0xaabbcc + 4);
    EXPECT_EQ(hex({r3.data(), 10}), "baaabbcc000000000000");

    const auto r4 = rlp::encode({buffer.get(), 0xffffff});
    EXPECT_EQ(r4.size(), 0xffffff + 4);
    EXPECT_EQ(hex({r4.data(), 10}), "baffffff000000000000");
}

TEST(state_rlp, encode_c_array)
{
    uint64_t a[]{1, 2, 3};
    EXPECT_EQ(hex(rlp::encode(a)), "c3010203");
}

TEST(state_rlp, encode_vector)
{
    const auto x = 0xe1e2e3e4e5e6e7d0d1d2d3d4d5d6d7c0c1c2c3c4c5c6c7b0b1b2b3b4b5b6b7_u256;
    EXPECT_EQ(
        rlp::encode(x), "9fe1e2e3e4e5e6e7d0d1d2d3d4d5d6d7c0c1c2c3c4c5c6c7b0b1b2b3b4b5b6b7"_hex);
    std::vector<uint256> v(0xffffff / 32, x);
    const auto r = rlp::encode(v);
    EXPECT_EQ(r.size(), v.size() * 32 + 4);
}

TEST(state_rlp, encode_account_with_balance)
{
    const auto expected =
        "f8 44"
        "80"
        "01"
        "a0 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        "a0 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"_hex;

    const auto r = rlp::encode_tuple(uint64_t{0}, 1_u256, emptyMPTHash, emptyBytesHash);
    EXPECT_EQ(r, expected);
}

TEST(state_rlp, encode_storage_value)
{
    const auto value = 0x00000000000000000000000000000000000000000000000000000000000001ff_bytes32;
    const auto xvalue = rlp::encode(rlp::trim(value));
    EXPECT_EQ(xvalue, "8201ff"_hex);
}

TEST(state_rlp, encode_mpt_node)
{
    const auto path = "2041"_hex;
    const auto value = "765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"_hex;
    const auto node = rlp::encode_tuple(path, value);
    EXPECT_EQ(node, "e18220419d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"_hex);
}

struct CustomStruct
{
    uint64_t a;
    bytes b;
};

inline bytes rlp_encode(const CustomStruct& t)
{
    return rlp::encode_tuple(t.a, t.b);
}

TEST(state_rlp, encode_custom_struct)
{
    const CustomStruct t{1, {0x02, 0x03}};
    EXPECT_EQ(rlp::encode(t), "c4 01 820203"_hex);
}

TEST(state_rlp, encode_custom_struct_list)
{
    std::vector<CustomStruct> v{{1, {0x02, 0x03}}, {4, {0x05, 0x06}}};
    EXPECT_EQ(rlp::encode(v), "ca c401820203 c404820506"_hex);
}

TEST(state_rlp, encode_uint64)
{
    EXPECT_EQ(rlp::encode(uint64_t{0}), "80"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{1}), "01"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x7f}), "7f"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x80}), "8180"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x81}), "8181"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xff}), "81ff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x0100}), "820100"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffff}), "82ffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x010000}), "83010000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffff}), "83ffffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x01000000}), "8401000000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffffff}), "84ffffffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x0100000000}), "850100000000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffffffff}), "85ffffffffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x010000000000}), "86010000000000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffffffffff}), "86ffffffffffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x01000000000000}), "8701000000000000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffffffffffff}), "87ffffffffffffff"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0x0100000000000000}), "880100000000000000"_hex);
    EXPECT_EQ(rlp::encode(uint64_t{0xffffffffffffffff}), "88ffffffffffffffff"_hex);
}

inline bytes to_significant_be_bytes(uint64_t x)
{
    const auto byte_width = (std::bit_width(x) + 7) / 8;
    const auto leading_zero_bits = std::countl_zero(x) & ~7;  // Leading bits rounded down to 8x.
    const auto trimmed_x = x << leading_zero_bits;            // Significant bytes moved to the top.

    uint8_t b[sizeof(x)];
    intx::be::store(b, trimmed_x);
    return bytes{b, static_cast<size_t>(byte_width)};
}

/// The "custom" implementation of RLP encoding of uint64. It trims leading zero bytes and
/// manually constructs bytes with variadic-length encoding.
inline bytes rlp_encode_uint64(uint64_t x)
{
    static constexpr uint8_t ShortBase = 0x80;
    if (x < ShortBase)  // Single-byte encoding.
        return bytes{(x == 0) ? ShortBase : static_cast<uint8_t>(x)};

    const auto b = to_significant_be_bytes(x);
    return static_cast<uint8_t>(ShortBase + b.size()) + b;
}

TEST(state_rlp, encode_uint64_custom)
{
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0}), "80"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{1}), "01"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x7f}), "7f"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x80}), "8180"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x81}), "8181"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xff}), "81ff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x0100}), "820100"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffff}), "82ffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x010000}), "83010000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffff}), "83ffffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x01000000}), "8401000000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffffff}), "84ffffffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x0100000000}), "850100000000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffffffff}), "85ffffffffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x010000000000}), "86010000000000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffffffffff}), "86ffffffffffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x01000000000000}), "8701000000000000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffffffffffff}), "87ffffffffffffff"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0x0100000000000000}), "880100000000000000"_hex);
    EXPECT_EQ(rlp_encode_uint64(uint64_t{0xffffffffffffffff}), "88ffffffffffffffff"_hex);
}
