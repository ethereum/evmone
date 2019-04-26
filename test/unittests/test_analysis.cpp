// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "utils.hpp"

#include <evmc/instructions.h>
#include <evmone/constants.hpp>
#include <evmone/execution.hpp>
#include <evmone/analysis.hpp>

#include <gtest/gtest.h>

constexpr auto rev = EVMC_BYZANTIUM;

int DELTA = evmone::JUMP_TABLE_CHECK_BOUNDARY;


const void** fake_fn_table = []() noexcept
{
    static int fake_values[evmone::JUMP_TABLE_SIZE] = { 0 };
    static const void* fake_labels[evmone::JUMP_TABLE_SIZE];
    for (size_t i = 0; i < evmone::JUMP_TABLE_SIZE; i++)
    {
        fake_labels[i] = static_cast<const void*>(&fake_values[i]);
    }
    return &fake_labels[0];
}
();



TEST(analysis, push_and_pop)
{
    auto code = from_hex("610102506801020304050607080950");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map, fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_PUSH2]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[OP_POP + DELTA]);
    EXPECT_EQ(analysis[2].opcode_dest, fake_fn_table[OP_PUSH9 + DELTA]);
    EXPECT_EQ(analysis[3].opcode_dest, fake_fn_table[OP_POP + DELTA]);
}


TEST(analysis, example1)
{
    auto code = from_hex("602a601e5359600055");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map, fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_PUSH1]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[DELTA + OP_PUSH1]);
    EXPECT_EQ(analysis[2].opcode_dest, fake_fn_table[DELTA + OP_MSTORE8]);
    EXPECT_EQ(analysis[3].opcode_dest, fake_fn_table[DELTA + OP_MSIZE]);
    EXPECT_EQ(analysis[4].opcode_dest, fake_fn_table[DELTA + OP_PUSH1]);
    EXPECT_EQ(analysis[5].opcode_dest, fake_fn_table[DELTA + OP_SSTORE]);

    EXPECT_EQ(analysis[0].block_data.gas_cost, 14);
    EXPECT_EQ(analysis[0].block_data.stack_req, 0);
    EXPECT_EQ(analysis[0].block_data.stack_max, 2);
}

TEST(analysis, stack_up_and_down)
{
    auto code = from_hex("81808080808080505050505050505050506000");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map,  fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_DUP2]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[DELTA + OP_DUP1]);
    EXPECT_EQ(analysis[7].opcode_dest, fake_fn_table[DELTA + OP_POP]);
    EXPECT_EQ(analysis[17].opcode_dest, fake_fn_table[DELTA + OP_PUSH1]);

    EXPECT_EQ(analysis[0].block_data.gas_cost, 7 * 3 + 10 * 2 + 3);
    EXPECT_EQ(analysis[0].block_data.stack_req, 3);
    EXPECT_EQ(analysis[0].block_data.stack_max, 7);
}

TEST(analysis, push)
{
    auto code = from_hex("6708070605040302017f00ee");
    evmone::instruction* jumpdest_map[code.size() + 2] = {nullptr};
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map, fake_fn_table, rev, &code[0], code.size());
    intx::uint256 result = *(intx::uint256*)(analysis[0].instruction_data.push_data.begin());
    intx::uint256 result_b = *(intx::uint256*)(analysis[1].instruction_data.push_data.begin());

    EXPECT_EQ(result.hi.lo, 0);
    EXPECT_EQ(result.lo.hi, 0);
    EXPECT_EQ(result.lo.lo, 0x0807060504030201);

    EXPECT_EQ(result_b.hi.hi, 0x00ee000000000000);
    EXPECT_EQ(result_b.hi.lo, 0);
    EXPECT_EQ(result_b.lo.hi, 0);
    EXPECT_EQ(result_b.lo.lo, 0);
}

TEST(analysis, jump1)
{
    auto code = from_hex("6002600401565b600360005260206000f3600656");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map,  fake_fn_table, rev, &code[0], code.size());
    EXPECT_EQ(jumpdest_map[6], &analysis[4 - 1]); // points to the instruction preceeding jumpdest
}

TEST(analysis, empty)
{
    bytes code;
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map,  fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_STOP]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[OP_STOP]);
}


TEST(analysis, only_jumpdest)
{
    auto code = from_hex("5b");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map,  fake_fn_table, rev, &code[0], code.size());

    evmone::instruction* expected = &analysis[0];
    EXPECT_EQ(jumpdest_map[0], expected - 1); // points to the instruction preceeding jumpdest
    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_JUMPDEST]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[OP_STOP]);
    EXPECT_EQ(analysis[2].opcode_dest, fake_fn_table[OP_STOP]);
}


TEST(analysis, jumpi_at_the_end)
{
    auto code = from_hex("57");
    evmone::instruction* jumpdest_map[code.size() + 2] = { nullptr };
    evmone::instruction analysis[code.size() + 2];
    evmone::analyze(analysis, jumpdest_map,  fake_fn_table, rev, &code[0], code.size());

    EXPECT_EQ(analysis[0].opcode_dest, fake_fn_table[OP_JUMPI]);
    EXPECT_EQ(analysis[1].opcode_dest, fake_fn_table[OP_STOP]);
    EXPECT_EQ(analysis[2].opcode_dest, fake_fn_table[OP_STOP]);
}
