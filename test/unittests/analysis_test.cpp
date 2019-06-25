// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;

constexpr auto rev = EVMC_BYZANTIUM;

const auto fake_fn_table = []() noexcept
{
    evmone::exec_fn_table fns;
    for (size_t i = 0; i < fns.size(); ++i)
        fns[i] = (evmone::exec_fn)i;
    return fns;
}
();


TEST(analysis, example1)
{
    const auto code = push(0x2a) + push(0x1e) + OP_MSTORE8 + OP_MSIZE + push(0) + OP_SSTORE;
    const auto analysis = analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 21);

    EXPECT_EQ(analysis.instrs[0].fn, fake_fn_table[OPX_BEGINBLOCK]);
    EXPECT_EQ(analysis.instrs[1].number, 0);
    EXPECT_EQ(analysis.instrs[2].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[3].value, 0x2a);
    EXPECT_EQ(analysis.instrs[4].value, 0);
    EXPECT_EQ(analysis.instrs[5].value, 0);
    EXPECT_EQ(analysis.instrs[6].value, 0);
    EXPECT_EQ(analysis.instrs[7].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[8].value, 0x1e);
    EXPECT_EQ(analysis.instrs[9].value, 0);
    EXPECT_EQ(analysis.instrs[10].value, 0);
    EXPECT_EQ(analysis.instrs[11].value, 0);
    EXPECT_EQ(analysis.instrs[12].fn, fake_fn_table[OP_MSTORE8]);
    EXPECT_EQ(analysis.instrs[13].fn, fake_fn_table[OP_MSIZE]);
    EXPECT_EQ(analysis.instrs[14].fn, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis.instrs[15].value, 0);
    EXPECT_EQ(analysis.instrs[16].value, 0);
    EXPECT_EQ(analysis.instrs[17].value, 0);
    EXPECT_EQ(analysis.instrs[18].value, 0);
    EXPECT_EQ(analysis.instrs[19].fn, fake_fn_table[OP_SSTORE]);
    EXPECT_EQ(analysis.instrs[20].fn, fake_fn_table[OP_STOP]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 14);
    EXPECT_EQ(analysis.blocks[0].stack_req, 0);
    EXPECT_EQ(analysis.blocks[0].stack_max, 2);
    EXPECT_EQ(analysis.blocks[0].stack_change, 0);
}

TEST(analysis, stack_up_and_down)
{
    const auto code = OP_DUP2 + 6 * OP_DUP1 + 10 * OP_POP + push(0);
    const auto analysis = analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 32);
    EXPECT_EQ(analysis.instrs[0].fn, fake_fn_table[OPX_BEGINBLOCK]);
    EXPECT_EQ(analysis.instrs[1].number, 0);
    EXPECT_EQ(analysis.instrs[2].fn, fake_fn_table[OP_DUP2]);
    EXPECT_EQ(analysis.instrs[3].number, 1);
    EXPECT_EQ(analysis.instrs[4].fn, fake_fn_table[OP_DUP1]);
    EXPECT_EQ(analysis.instrs[5].number, 0);
    EXPECT_EQ(analysis.instrs[14].fn, fake_fn_table[OP_DUP1]);
    EXPECT_EQ(analysis.instrs[15].number, 0);
    EXPECT_EQ(analysis.instrs[16].fn, fake_fn_table[OP_POP]);
    EXPECT_EQ(analysis.instrs[26].fn, fake_fn_table[OP_PUSH1]);

    ASSERT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.blocks[0].gas_cost, 7 * 3 + 10 * 2 + 3);
    EXPECT_EQ(analysis.blocks[0].stack_req, 3);
    EXPECT_EQ(analysis.blocks[0].stack_max, 7);
    EXPECT_EQ(analysis.blocks[0].stack_change, -2);
}

TEST(analysis, push)
{
    const auto code = push(0x0807060504030201) + "7f00ee";
    const auto analysis = analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.instrs.size(), 13);
    ASSERT_EQ(analysis.args_storage.size(), 0);
    EXPECT_EQ(analysis.instrs[0].fn, fake_fn_table[OPX_BEGINBLOCK]);
    EXPECT_EQ(analysis.instrs[2].fn, fake_fn_table[OP_PUSH8]);
    EXPECT_EQ(analysis.instrs[3].value, 0x0807060504030201);
    EXPECT_EQ(analysis.instrs[4].value, 0);
    EXPECT_EQ(analysis.instrs[5].value, 0);
    EXPECT_EQ(analysis.instrs[6].value, 0);
    EXPECT_EQ(analysis.instrs[7].fn, fake_fn_table[OP_PUSH32]);
    EXPECT_EQ(analysis.instrs[8].value, 0);
    EXPECT_EQ(analysis.instrs[9].value, 0);
    EXPECT_EQ(analysis.instrs[10].value, 0);
    EXPECT_EQ(analysis.instrs[11].value, 0x00ee000000000000);
}

TEST(analysis, jump1)
{
    const auto code = jump(add(4, 2)) + OP_JUMPDEST + mstore(0, 3) + ret(0, 0x20) + jump(6);
    const auto analysis = analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.blocks.size(), 3);
    ASSERT_EQ(analysis.jumpdest_offsets.size(), 1);
    ASSERT_EQ(analysis.jumpdest_targets.size(), 1);
    EXPECT_EQ(analysis.jumpdest_offsets[0], 6);
    EXPECT_EQ(analysis.jumpdest_targets[0], 14);
    EXPECT_EQ(find_jumpdest(analysis, 6), 14);
    EXPECT_EQ(find_jumpdest(analysis, 0), -1);
    EXPECT_EQ(find_jumpdest(analysis, 7), -1);
}

TEST(analysis, empty)
{
    bytes code;
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis.blocks.size(), 0);
    EXPECT_EQ(analysis.instrs.size(), 1);
    EXPECT_EQ(analysis.instrs.back().fn, fake_fn_table[OP_STOP]);
}

TEST(analysis, only_jumpdest)
{
    auto code = from_hex("5b");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());

    ASSERT_EQ(analysis.blocks.size(), 1);
    ASSERT_EQ(analysis.jumpdest_offsets.size(), 1);
    ASSERT_EQ(analysis.jumpdest_targets.size(), 1);
    EXPECT_EQ(analysis.jumpdest_offsets[0], 0);
    EXPECT_EQ(analysis.jumpdest_targets[0], 0);
}

TEST(analysis, jumpi_at_the_end)
{
    auto code = from_hex("57");
    auto analysis = evmone::analyze(fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis.blocks.size(), 1);
    EXPECT_EQ(analysis.instrs.back().fn, fake_fn_table[OP_STOP]);
}