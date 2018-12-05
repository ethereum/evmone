// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>

#include <gtest/gtest.h>

using bytes = std::basic_string<uint8_t>;

inline bytes from_hex(const char hex[]) noexcept
{
    bytes bs;
    int b = 0;
    for (size_t i = 0; hex[i] != 0; ++i)
    {
        auto h = hex[i];
        int v = (h <= '9') ? h - '0' : h - 'a' + 10;

        if (i % 2 == 0)
            b = v << 4;
        else
            bs.push_back(static_cast<uint8_t>(b | v));
    }
    return bs;
}


TEST(analysis, example1)
{
    auto code = from_hex("602a601e5359600055");

    evmone::exec_fn_table fns;
    for (size_t i = 0; i < fns.size(); ++i)
        fns[i] = (evmone::exec_fn)i;

    auto analysis = evmone::analyze(fns, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 7);

    EXPECT_EQ(analysis.instrs[0].fn, fns[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[1].fn, fns[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[2].fn, fns[OP_MSTORE8]);
    EXPECT_EQ(analysis.instrs[3].fn, fns[OP_MSIZE]);
    EXPECT_EQ(analysis.instrs[4].fn, fns[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[5].fn, fns[OP_SSTORE]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 14);
    EXPECT_EQ(analysis.blocks[0].stack_req, 0);
    EXPECT_EQ(analysis.blocks[0].stack_max, 2);
    EXPECT_EQ(analysis.blocks[0].stack_diff, 0);
}

TEST(analysis, stack_up_and_down)
{
    auto code = from_hex("81808080808080505050505050505050506000");

    evmone::exec_fn_table fns;
    for (size_t i = 0; i < fns.size(); ++i)
        fns[i] = (evmone::exec_fn)i;

    auto analysis = evmone::analyze(fns, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 19);
    EXPECT_EQ(analysis.instrs[0].fn, fns[OP_DUP2]);
    EXPECT_EQ(analysis.instrs[1].fn, fns[OP_DUP1]);
    EXPECT_EQ(analysis.instrs[7].fn, fns[OP_POP]);
    EXPECT_EQ(analysis.instrs[17].fn, fns[OP_PUSH1]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 7 * 3 + 10 * 2 + 3);
    EXPECT_EQ(analysis.blocks[0].stack_req, 3);
    EXPECT_EQ(analysis.blocks[0].stack_max, 7);
    EXPECT_EQ(analysis.blocks[0].stack_diff, -2);
}