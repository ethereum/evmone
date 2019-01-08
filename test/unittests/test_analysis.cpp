// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "utils.hpp"

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>

#include <gtest/gtest.h>

constexpr auto rev = EVMC_BYZANTIUM;

TEST(analysis, example1)
{
    auto code = from_hex("602a601e5359600055");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 7);

    EXPECT_EQ(analysis.instrs[0].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[1].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[2].fn, fake_fn_table[OP_MSTORE8]);
    EXPECT_EQ(analysis.instrs[3].fn, fake_fn_table[OP_MSIZE]);
    EXPECT_EQ(analysis.instrs[4].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[5].fn, fake_fn_table[OP_SSTORE]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 14);
    EXPECT_EQ(analysis.blocks[0].stack_req, 0);
    EXPECT_EQ(analysis.blocks[0].stack_max, 2);
    EXPECT_EQ(analysis.blocks[0].stack_diff, 0);
}

TEST(analysis, stack_up_and_down)
{
    auto code = from_hex("81808080808080505050505050505050506000");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 19);
    EXPECT_EQ(analysis.instrs[0].fn, fake_fn_table[OP_DUP2]);
    EXPECT_EQ(analysis.instrs[1].fn, fake_fn_table[OP_DUP1]);
    EXPECT_EQ(analysis.instrs[7].fn, fake_fn_table[OP_POP]);
    EXPECT_EQ(analysis.instrs[17].fn, fake_fn_table[OP_PUSH1]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 7 * 3 + 10 * 2 + 3);
    EXPECT_EQ(analysis.blocks[0].stack_req, 3);
    EXPECT_EQ(analysis.blocks[0].stack_max, 7);
    EXPECT_EQ(analysis.blocks[0].stack_diff, -2);
}

TEST(analysis, push)
{
    auto code = from_hex("6708070605040302017f00ee");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());
    dump_analysis(analysis);

    ASSERT_EQ(analysis.instrs.size(), 3);
    ASSERT_EQ(analysis.args_storage.size(), 2);
    EXPECT_EQ(analysis.instrs[0].arg.data, &analysis.args_storage[0][0]);
    EXPECT_EQ(analysis.instrs[1].arg.data, &analysis.args_storage[1][0]);
    EXPECT_EQ(analysis.args_storage[0][31 - 7], 0x08);
    EXPECT_EQ(analysis.args_storage[1][1], 0xee);
}

TEST(analysis, jump1)
{
    auto code = from_hex("6002600401565b600360005260206000f3600656");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());
    dump_analysis(analysis);

    ASSERT_EQ(analysis.blocks.size(), 3);
    ASSERT_EQ(analysis.jumpdest_map.size(), 1);
    EXPECT_EQ(analysis.jumpdest_map[0], std::pair(6, 4));
    EXPECT_EQ(analysis.find_jumpdest(6), 4);
    EXPECT_EQ(analysis.find_jumpdest(0), -1);
}

TEST(analysis, empty)
{
    bytes code;
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());
    dump_analysis(analysis);

    EXPECT_EQ(analysis.blocks.size(), 0);
    EXPECT_EQ(analysis.instrs.size(), 0);
}

TEST(analysis, only_jumpdest)
{
    auto code = from_hex("5b");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());
    dump_analysis(analysis);

    ASSERT_EQ(analysis.blocks.size(), 1);
    ASSERT_EQ(analysis.jumpdest_map.size(), 1);
    EXPECT_EQ(analysis.jumpdest_map[0], std::pair(0, 0));
}

TEST(analysis, jumpi_at_the_end)
{
    auto code = from_hex("57");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());
    dump_analysis(analysis);

    EXPECT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.instrs.back().fn, fake_fn_table[OP_STOP]);
}