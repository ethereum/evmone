// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "utils.hpp"

#include <evmone/execution.hpp>

#include <gtest/gtest.h>

TEST(execution, push_and_pop)
{
    auto code = from_hex("610102506801020304050607080950");

    auto r = evmone::execute(11, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 1);
}

TEST(execution, stack_underflow)
{
    auto code = from_hex("61010250680102030405060708095050");

    auto r = evmone::execute(13, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_STACK_UNDERFLOW);
    EXPECT_EQ(r.gas_left, 0);
}

TEST(execution, add)
{
    auto code = from_hex("6007600d0160005260206000f3");
    auto r = evmone::execute(25, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 1);
    EXPECT_EQ(r.output_size, 32);
    EXPECT_EQ(r.output_data[31], 20);
    r.release(&r);
}

TEST(execution, dup)
{
    // 0 7 3 5
    // 0 7 3 5 3 5
    // 0 7 3 5 3 5 5 7
    // 0 7 3 5 20
    // 0 7 3 5 (20 0)
    // 0 7 3 5 3 0
    auto code = from_hex("6000600760036005818180850101018452602084f3");
    auto r = evmone::execute(49, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 1);
    EXPECT_EQ(r.output_size, 32);
    EXPECT_EQ(r.output_data[31], 20);
    r.release(&r);
}

TEST(execution, sub_and_swap)
{
    auto code = from_hex("600180810380829052602090f3");
    auto r = evmone::execute(33, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    EXPECT_EQ(r.output_size, 32);
    EXPECT_EQ(r.output_data[31], 1);
    r.release(&r);
}

TEST(execution, memory_and_not)
{
    auto code = from_hex("600060018019815381518252800190f3");
    auto r = evmone::execute(42, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    EXPECT_EQ(r.output_size, 2);
    EXPECT_EQ(r.output_data[1], 0xfe);
    EXPECT_EQ(r.output_data[0], 0);
    r.release(&r);
}

TEST(execution, msize)
{
    auto code = from_hex("60aa6022535960005360016000f3");
    auto r = evmone::execute(29, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    EXPECT_EQ(r.output_size, 1);
    EXPECT_EQ(r.output_data[0], 0x40);
    r.release(&r);
}

TEST(execution, gas)
{
    auto code = from_hex("5a5a5a010160005360016000f3");
    auto r = evmone::execute(40, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 13);
    EXPECT_EQ(r.output_size, 1);
    EXPECT_EQ(r.output_data[0], 38 + 36 + 34);
    r.release(&r);
}

TEST(execution, arith)
{
    // x = (0 - 1) * 3
    // y = 17 s/ x
    // z = 17 s% x
    // a = 17 * x + z
    // iszero
    std::string s;
    s += "60116001600003600302";  // 17 -3
    s += "808205";                // 17 -3 -5
    s += "818307";                // 17 -3 -5 2
    s += "910201";                // 17 17
    s += "0315";                  // 1
    s += "60005360016000f3";
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(100, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 26);
    EXPECT_EQ(r.output_size, 1);
    EXPECT_EQ(r.output_data[0], 1);
    r.release(&r);
}

TEST(execution, comparison)
{
    std::string s;
    s += "60006001808203";  // 0 1 -1
    s += "818110600053";    // m[0] = -1 < 1
    s += "818111600153";    // m[1] = -1 > 1
    s += "818112600253";    // m[2] = -1 s< 1
    s += "818113600353";    // m[3] = -1 s> 1
    s += "818114600453";    // m[4] = -1 == 1
    s += "60056000f3";
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(100, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 1);
    EXPECT_EQ(r.output_size, 5);
    EXPECT_EQ(r.output_data[0], 0);
    EXPECT_EQ(r.output_data[1], 1);
    EXPECT_EQ(r.output_data[2], 1);
    EXPECT_EQ(r.output_data[3], 0);
    EXPECT_EQ(r.output_data[4], 0);
    r.release(&r);
}

TEST(execution, bitwise)
{
    std::string s;
    s += "60aa60ff";      // aa ff
    s += "818116600053";  // m[0] = aa & ff
    s += "818117600153";  // m[1] = aa | ff
    s += "818118600253";  // m[2] = aa ^ ff
    s += "60036000f3";
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(60, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 3);
    EXPECT_EQ(r.output_data[0], 0xaa & 0xff);
    EXPECT_EQ(r.output_data[1], 0xaa | 0xff);
    EXPECT_EQ(r.output_data[2], 0xaa ^ 0xff);
    r.release(&r);
}

TEST(execution, jump)
{
    std::string s;
    s += "60be600053";  // m[0] = be
    s += "60fa";        // fa
    s += "60055801";    // PC + 5
    s += "56";          // JUMP
    s += "5050";        // POP x2
    s += "5b";          // JUMPDEST
    s += "600153";      // m[1] = fa
    s += "60026000f3";  // RETURN(0,2)
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(44, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 2);
    EXPECT_EQ(r.output_data[0], 0xbe);
    EXPECT_EQ(r.output_data[1], 0xfa);
    r.release(&r);
}

TEST(execution, jumpi)
{
    std::string s;
    s += "5a600557";      // GAS 5 JUMPI
    s += "00";            // STOP
    s += "5b60016000f3";  // JUMPDEST RETURN(0,1)
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(25, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 1);
    EXPECT_EQ(r.output_data[0], 0);
    r.release(&r);
}


TEST(execution, byte)
{
    std::string s;
    s += "63aabbccdd";  // aabbccdd
    s += "8060001a";    // DUP 1 BYTE
    s += "600053";      // m[0] = 00
    s += "80601c1a";    // DUP 28 BYTE
    s += "600253";      // m[2] = aa
    s += "80601f1a";    // DUP 31 BYTE
    s += "600453";      // m[4] = dd
    s += "60056000f3";  // RETURN(0,5)
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(57, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 5);
    EXPECT_EQ(r.output_data[0], 0);
    EXPECT_EQ(r.output_data[2], 0xaa);
    EXPECT_EQ(r.output_data[4], 0xdd);
    r.release(&r);
}

TEST(execution, addmod_mulmod)
{
    std::string s;
    s += "7fcdeb8272fc01d4d50a6ec165d2ea477af19b9b2c198459f59079583b97e88a66";
    s += "7f52e7e7a03b86f534d2e338aa1bb05ba3539cb2f51304cdbce69ce2d422c456ca";
    s += "7fe0f2f0cae05c220260e1724bdc66a0f83810bd1217bd105cb2da11e257c6cdf6";
    s += "82828208";    // DUP DUP DUP ADDMOD
    s += "600052";      // m[0..]
    s += "82828209";    // DUP DUP DUP MULMOD
    s += "602052";      // m[32..]
    s += "60406000f3";  // RETURN(0,64)
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(67, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 64);
    auto a = from_hex("65ef55f81fe142622955e990252cb5209a11d4db113d842408fd9c7ae2a29a5a");
    EXPECT_EQ(a, bytes(&r.output_data[0], 32));
    auto p = from_hex("34e04890131a297202753cae4c72efd508962c9129aed8b08c8e87ab425b7258");
    EXPECT_EQ(p, bytes(&r.output_data[32], 32));
    r.release(&r);
}

TEST(execution, signextend)
{
    std::string s;
    s += "62017ffe";    // 017ffe
    s += "8060000b";    // DUP SIGNEXTEND(0)
    s += "600052";      // m[0..]
    s += "8060010b";    // DUP SIGNEXTEND(1)
    s += "602052";      // m[32..]
    s += "60406000f3";  // RETURN(0,64)
    auto code = from_hex(s.c_str());
    auto r = evmone::execute(49, &code[0], code.size());
    EXPECT_EQ(r.status_code, EVMC_SUCCESS);
    EXPECT_EQ(r.gas_left, 0);
    ASSERT_EQ(r.output_size, 64);
    auto a = from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    EXPECT_EQ(bytes(&r.output_data[0], 32), a);
    auto b = from_hex("0000000000000000000000000000000000000000000000000000000000007ffe");
    EXPECT_EQ(bytes(&r.output_data[32], 32), b);
    r.release(&r);
}
