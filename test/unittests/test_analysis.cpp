// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>

#include <gtest/gtest.h>
#include <iostream>

using bytes = std::basic_string<uint8_t>;

const auto fake_fn_table = []() noexcept
{
    evmone::exec_fn_table fns;
    for (size_t i = 0; i < fns.size(); ++i)
        fns[i] = (evmone::exec_fn)i;
    return fns;
}
();

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

std::string to_hex(const uint8_t bytes[], size_t size)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        str.push_back(hex_chars[bytes[i] >> 4]);
        str.push_back(hex_chars[bytes[i] & 0xf]);
    }
    return str;
}

void dump_analysis(const evmone::code_analysis& analysis)
{
    auto names = evmc_get_instruction_names_table(EVMC_BYZANTIUM);

    for (auto& instr : analysis.instrs)
    {
        auto c = static_cast<uint8_t>((size_t)instr.fn);
        auto name = names[c];
        if (!name)
            name = "XX";

        std::cout << name;
        if (instr.extra_data_index >= 0)
            std::cout << '\t' << to_hex(analysis.extra[size_t(instr.extra_data_index)].bytes, 32);
        std::cout << '\n';
    }

    for (auto& b : analysis.blocks)
    {
        std::cout << "<" << b.gas_cost << ">\n";
    }
}


TEST(analysis, example1)
{
    auto code = from_hex("602a601e5359600055");

    auto analysis = evmone::analyze(fake_fn_table, &code[0], code.size());

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

    auto analysis = evmone::analyze(fake_fn_table, &code[0], code.size());

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
    auto analysis = evmone::analyze(fake_fn_table, &code[0], code.size());
    dump_analysis(analysis);

    ASSERT_EQ(analysis.instrs.size(), 3);
    ASSERT_EQ(analysis.extra.size(), 2);
    EXPECT_EQ(analysis.instrs[0].extra_data_index, 0);
    EXPECT_EQ(analysis.instrs[1].extra_data_index, 1);
    EXPECT_EQ(analysis.extra[0].bytes[31 - 7], 0x08);
    EXPECT_EQ(analysis.extra[1].bytes[1], 0xee);
}

TEST(analysis, jump1)
{
    auto code = from_hex("6002600401565b600360005260206000f3600656");

    auto analysis = evmone::analyze(fake_fn_table, &code[0], code.size());
    dump_analysis(analysis);

    FAIL();
}