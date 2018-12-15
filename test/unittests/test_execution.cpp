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
