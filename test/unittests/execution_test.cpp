// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmone/evmone.h>

#include <evmc/helpers.hpp>
#include <evmc/instructions.h>
#include <gtest/gtest.h>
#include <intx/intx.hpp>
#include <test/utils/utils.hpp>
#include <algorithm>
#include <numeric>
#include <unordered_map>


// Helpers for bytecode.
#define _(x) x
#define ISZERO() "15"
#define NOT(x) PUSH(x) "19"
#define SHA3(index, size) PUSH(size) PUSH(index) "20"
#define MSTORE8(index) PUSH(index) "53"
#define PUSH(x) "60" #x
#define PUSH2(x) "61" #x
#define DUP() "80"
#define CALLDATALOAD(index) PUSH(index) "35"
#define RETURN(size) PUSH(size) PUSH(00) "f3"
#define MSTORE(index) PUSH(index) "52"
#define SSTORE(index) PUSH(index) "55"

/// Return top stack item.
#define RETTOP() MSTORE(00) RETURN(20)

#define _2x(x) x x
#define _3x(x) x x x
#define _4x(x) x x x x
#define _6x(x) x x x x x x

using namespace std::literals;

extern evmc_host_interface interface;

class execution : public testing::Test, public evmc_context
{
protected:
    evmc_instance* vm = nullptr;
    evmc_revision rev = EVMC_BYZANTIUM;  // Use Byzantium by default.
    evmc_message msg = {};
    evmc_result result = {};
    int64_t gas_used = 0;

    evmc_address last_accessed_account = {};

    std::unordered_map<evmc_bytes32, evmc_bytes32> storage;
    bool storage_cold = true;

    evmc_tx_context tx_context = {};

    bytes log_data;
    std::vector<evmc_bytes32> log_topics;

    evmc_address selfdestruct_beneficiary = {};

    evmc_bytes32 blockhash = {};

    bool exists = false;
    intx::uint256 balance = {};
    bytes extcode = {};

    evmc_message call_msg = {};  ///< Recorded call message.
    evmc_result call_result = {};

    static evmc_host_interface interface;

    execution() noexcept : evmc_context{&interface}, vm{evmc_create_evmone()} {}

    ~execution() noexcept override
    {
        // Release the attached EVM execution result.
        if (result.release)
            result.release(&result);
    }

    /// Wrapper for evmone::execute. The result will be in the .result field.
    void execute(int64_t gas, std::string_view code_hex, std::string_view input_hex = {}) noexcept
    {
        auto input = from_hex(input_hex);
        msg.gas = gas;
        msg.input_data = input.data();
        msg.input_size = input.size();
        execute(msg, code_hex);
    }

    void execute(std::string_view code_hex, std::string_view input_hex = {}) noexcept
    {
        execute(std::numeric_limits<int64_t>::max(), code_hex, input_hex);
    }

    /// Wrapper for evmone::execute. The result will be in the .result field.
    void execute(const evmc_message& msg, std::string_view code_hex) noexcept
    {
        // Release previous result.
        if (result.release)
            result.release(&result);

        auto code = from_hex(code_hex.data());
        result = vm->execute(vm, this, rev, &msg, &code[0], code.size());
        gas_used = msg.gas - result.gas_left;
    }
};

evmc_host_interface execution::interface = {
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<execution*>(ctx);
        e.last_accessed_account = *addr;
        return e.exists;
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key) {
        return static_cast<execution*>(ctx)->storage[*key];
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key, const evmc_bytes32* value) {
        auto& old = static_cast<execution*>(ctx)->storage[*key];

        evmc_storage_status status;
        if (old == *value)
            status = EVMC_STORAGE_UNCHANGED;
        else if (is_zero(old))
            status = EVMC_STORAGE_ADDED;
        else if (is_zero(*value))
            status = EVMC_STORAGE_DELETED;
        else if (static_cast<execution*>(ctx)->storage_cold)
            status = EVMC_STORAGE_MODIFIED;
        else
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        old = *value;
        return status;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<execution*>(ctx);
        e.last_accessed_account = *addr;
        evmc_uint256be b = {};
        intx::be::store(b.bytes, e.balance);
        return b;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<execution*>(ctx);
        e.last_accessed_account = *addr;
        return e.extcode.size();
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<execution*>(ctx);
        e.last_accessed_account = *addr;
        auto hash = evmc_bytes32{};
        std::fill(std::begin(hash.bytes), std::end(hash.bytes), uint8_t{0xee});
        return hash;
    },
    [](evmc_context* ctx, const evmc_address* addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) {
        auto& e = *static_cast<execution*>(ctx);
        e.last_accessed_account = *addr;
        std::copy_n(&e.extcode[code_offset], buffer_size, buffer_data);
        return buffer_size;
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_address* beneficiary) {
        static_cast<execution*>(ctx)->selfdestruct_beneficiary = *beneficiary;
    },
    [](evmc_context* ctx, const evmc_message* msg) {
        auto& e = *static_cast<execution*>(ctx);
        e.call_msg = *msg;
        return e.call_result;
    },
    [](evmc_context* ctx) { return static_cast<execution*>(ctx)->tx_context; },
    [](evmc_context* ctx, int64_t) { return static_cast<execution*>(ctx)->blockhash; },
    [](evmc_context* ctx, const evmc_address*, const uint8_t* data, size_t data_size,
        const evmc_bytes32 topics[], size_t topics_count) {
        auto& e = *static_cast<execution*>(ctx);
        e.log_data.assign(data, data_size);
        e.log_topics.reserve(topics_count);
        std::copy_n(topics, topics_count, std::back_inserter(e.log_topics));
    },
};

TEST_F(execution, push_and_pop)
{
    execute(11, "610102506801020304050607080950");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 1);
}

TEST_F(execution, stack_underflow)
{
    execute(13, "61010250680102030405060708095050");
    EXPECT_EQ(result.status_code, EVMC_STACK_UNDERFLOW);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, add)
{
    execute(25, "6007600d0160005260206000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 1);
    EXPECT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[31], 20);
}

TEST_F(execution, dup)
{
    // 0 7 3 5
    // 0 7 3 5 3 5
    // 0 7 3 5 3 5 5 7
    // 0 7 3 5 20
    // 0 7 3 5 (20 0)
    // 0 7 3 5 3 0
    execute(49, "6000600760036005818180850101018452602084f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 1);
    EXPECT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[31], 20);
}

TEST_F(execution, dup_all_1)
{
    execute(PUSH(01) _("808182838485868788898a8b8c8d8e8f") _("01010101010101010101010101010101")
            RETTOP());

    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.output_data[31], 17);
}

TEST_F(execution, dup_stack_overflow)
{
    auto code = std::string{PUSH(01) _("808182838485868788898a8b8c8d8e8f")};
    for (int i = 0; i < (1024 - 17); ++i)
        code += "8f";

    execute(code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    execute(code + "8f");
    EXPECT_EQ(result.status_code, EVMC_STACK_OVERFLOW);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, sub_and_swap)
{
    execute(33, "600180810380829052602090f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[31], 1);
}

TEST_F(execution, memory_and_not)
{
    execute(42, "600060018019815381518252800190f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.output_size, 2);
    EXPECT_EQ(result.output_data[1], 0xfe);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, msize)
{
    execute(29, "60aa6022535960005360016000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0x40);
}

TEST_F(execution, gas)
{
    execute(40, "5a5a5a010160005360016000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 13);
    EXPECT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 38 + 36 + 34);
}

TEST_F(execution, arith)
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
    execute(100, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 26);
    EXPECT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_F(execution, comparison)
{
    std::string s;
    s += "60006001808203808001";  // 0 1 -1 -2
    s += "828210600053";          // m[0] = -1 < 1
    s += "828211600153";          // m[1] = -1 > 1
    s += "828212600253";          // m[2] = -1 s< 1
    s += "828213600353";          // m[3] = -1 s> 1
    s += "828214600453";          // m[4] = -1 == 1
    s += "818112600553";          // m[5] = -2 s< -1
    s += "818113600653";          // m[6] = -2 s> -1
    s += "60076000f3";
    execute(s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 138);
    ASSERT_EQ(result.output_size, 7);
    EXPECT_EQ(result.output_data[0], 0);
    EXPECT_EQ(result.output_data[1], 1);
    EXPECT_EQ(result.output_data[2], 1);
    EXPECT_EQ(result.output_data[3], 0);
    EXPECT_EQ(result.output_data[4], 0);
    EXPECT_EQ(result.output_data[5], 1);
    EXPECT_EQ(result.output_data[6], 0);
}

TEST_F(execution, bitwise)
{
    std::string s;
    s += "60aa60ff";      // aa ff
    s += "818116600053";  // m[0] = aa & ff
    s += "818117600153";  // m[1] = aa | ff
    s += "818118600253";  // m[2] = aa ^ ff
    s += "60036000f3";
    execute(60, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 3);
    EXPECT_EQ(result.output_data[0], 0xaa & 0xff);
    EXPECT_EQ(result.output_data[1], 0xaa | 0xff);
    EXPECT_EQ(result.output_data[2], 0xaa ^ 0xff);
}

TEST_F(execution, jump)
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
    execute(44, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 2);
    EXPECT_EQ(result.output_data[0], 0xbe);
    EXPECT_EQ(result.output_data[1], 0xfa);
}

TEST_F(execution, jumpi)
{
    std::string s;
    s += "5a600557";      // GAS 5 JUMPI
    s += "00";            // STOP
    s += "5b60016000f3";  // JUMPDEST RETURN(0,1)
    execute(25, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, jumpi_else)
{
    execute(15, "418057");  // COINBASE DUP JUMPI (STOP)
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.output_size, 0);
}

TEST_F(execution, jumpi_at_the_end)
{
    execute(1000, "5b6001600057");
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(gas_used, 1000);
}

TEST_F(execution, bad_jumpdest)
{
    tx_context.block_number = 1;
    tx_context.block_gas_limit = 0;
    tx_context.block_timestamp = 0x80000000;
    for (auto op : {OP_JUMP, OP_JUMPI})
    {
        execute("4345" + hex(op));
        EXPECT_EQ(result.status_code, EVMC_BAD_JUMP_DESTINATION);
        EXPECT_EQ(result.gas_left, 0);

        execute("4342" + hex(op));
        EXPECT_EQ(result.status_code, EVMC_BAD_JUMP_DESTINATION);
        EXPECT_EQ(result.gas_left, 0);
    }
}

TEST_F(execution, byte)
{
    std::string s;
    s += "63aabbccdd";  // aabbccdd
    s += "8060001a";    // DUP 1 BYTE
    s += "600053";      // m[0] = 00
    s += "80601c1a";    // DUP 28 BYTE
    s += "600253";      // m[2] = aa
    s += "80601f1a";    // DUP 31 BYTE
    s += "600453";      // m[4] = dd
    s += "8060201a";    // DUP 32 BYTE
    s += "600653";      // m[6] = 00
    s += "60076000f3";  // RETURN(0,7)
    execute(72, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 7);
    EXPECT_EQ(result.output_data[0], 0);
    EXPECT_EQ(result.output_data[2], 0xaa);
    EXPECT_EQ(result.output_data[4], 0xdd);
    EXPECT_EQ(result.output_data[6], 0);
}

TEST_F(execution, addmod_mulmod)
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
    execute(67, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 64);
    auto a = from_hex("65ef55f81fe142622955e990252cb5209a11d4db113d842408fd9c7ae2a29a5a");
    EXPECT_EQ(a, bytes(&result.output_data[0], 32));
    auto p = from_hex("34e04890131a297202753cae4c72efd508962c9129aed8b08c8e87ab425b7258");
    EXPECT_EQ(p, bytes(&result.output_data[32], 32));
}

TEST_F(execution, divmod)
{
    // Div and mod the -1 by the input and return.
    execute("600035600160000381810460005281810660205260406000f3", "0d");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 61);
    ASSERT_EQ(result.output_size, 64);
    auto a = from_hex("0000000000000000000000000000000000000000000000000000000000000013");
    EXPECT_EQ(a, bytes(&result.output_data[0], 32));
    auto p = from_hex("08ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(p, bytes(&result.output_data[32], 32));
}

TEST_F(execution, div_by_zero)
{
    rev = EVMC_CONSTANTINOPLE;
    auto s = std::string{};
    s += "60008060ff";  // 0 0 ff
    s += "0405600055";  // s[0] = 0
    execute(222, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    auto it = storage.find({});
    ASSERT_NE(it, storage.end());
    EXPECT_EQ(it->second, evmc_bytes32{});
}

TEST_F(execution, mod_by_zero)
{
    execute("60008060ff0607600055");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 5022);
    auto it = storage.find({});
    ASSERT_NE(it, storage.end());
    EXPECT_EQ(it->second, evmc_bytes32{});
}

TEST_F(execution, addmod_mulmod_by_zero)
{
    execute("6000358080808008091560005260206000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 52);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[31], 1);
}

TEST_F(execution, signextend)
{
    std::string s;
    s += "62017ffe";    // 017ffe
    s += "8060000b";    // DUP SIGNEXTEND(0)
    s += "600052";      // m[0..]
    s += "8060010b";    // DUP SIGNEXTEND(1)
    s += "602052";      // m[32..]
    s += "60406000f3";  // RETURN(0,64)
    execute(49, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 64);
    auto a = from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    EXPECT_EQ(bytes(&result.output_data[0], 32), a);
    auto b = from_hex("0000000000000000000000000000000000000000000000000000000000007ffe");
    EXPECT_EQ(bytes(&result.output_data[32], 32), b);
}

TEST_F(execution, signextend_31)
{
    rev = EVMC_CONSTANTINOPLE;

    execute("61010160000360081c601e0b60005260206000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 38);
    ASSERT_EQ(result.output_size, 32);
    auto a = from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    EXPECT_EQ(bytes(&result.output_data[0], 32), a);

    execute("61010160000360081c601f0b60005260206000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 38);
    ASSERT_EQ(result.output_size, 32);
    a = from_hex("00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    EXPECT_EQ(bytes(&result.output_data[0], 32), a);
}

TEST_F(execution, exp)
{
    std::string s;
    s += "612019";      // 0x2019
    s += "6003";        // 3
    s += "0a";          // EXP
    s += "600052";      // m[0..]
    s += "60206000f3";  // RETURN(0,32)
    execute(131, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 32);
    auto a = from_hex("263cf24662b24c371a647c1340022619306e431bf3a4298d4b5998a3f1c1aaa3");
    EXPECT_EQ(bytes(&result.output_data[0], 32), a);
}

TEST_F(execution, exp_oog)
{
    auto code = "6001600003800a";
    execute(1622, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);

    execute(1621, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, exp_pre_sd)
{
    rev = EVMC_TANGERINE_WHISTLE;
    std::string s;
    s += "62012019";    // 0x012019
    s += "6003";        // 3
    s += "0a";          // EXP
    s += "600052";      // m[0..]
    s += "60206000f3";  // RETURN(0,32)
    execute(131 - 70, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 32);
    auto a = from_hex("422ea3761c4f6517df7f102bb18b96abf4735099209ca21256a6b8ac4d1daaa3");
    EXPECT_EQ(bytes(&result.output_data[0], 32), a);
}

TEST_F(execution, calldataload)
{
    std::string s;
    s += "600335";      // CALLDATALOAD(3)
    s += "600052";      // m[0..]
    s += "600a6000f3";  // RETURN(0,10)
    execute(21, s, "0102030405");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 10);
    auto a = from_hex("04050000000000000000");
    EXPECT_EQ(bytes(&result.output_data[0], 10), a);
}

TEST_F(execution, calldataload_outofrange)
{
    execute(CALLDATALOAD(01) RETTOP());
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(std::count(result.output_data, result.output_data + result.output_size, 0), 32);
}

TEST_F(execution, calldatacopy)
{
    std::string s;
    s += "366001600037";  // CALLDATASIZE 1 0 CALLDATACOPY
    s += "600a6000f3";    // RETURN(0,10)
    execute(s, "0102030405");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 23);
    ASSERT_EQ(result.output_size, 10);
    auto a = from_hex("02030405000000000000");
    EXPECT_EQ(bytes(&result.output_data[0], 10), a);

    execute(s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 20);

    execute("60ff66fffffffffffffa60003760ff6000f3");
    EXPECT_EQ(gas_used, 66);
    ASSERT_EQ(result.output_size, 0xff);
    EXPECT_EQ(std::count(result.output_data, result.output_data + result.output_size, 0), 0xff);
}

TEST_F(execution, address)
{
    std::string s;
    s += "30600052";    // ADDRESS MSTORE(0)
    s += "600a600af3";  // RETURN(10,10)
    evmc_message msg = {};
    msg.gas = 17;
    msg.destination.bytes[0] = 0xcc;
    execute(msg, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 10);
    auto a = from_hex("0000cc00000000000000");
    EXPECT_EQ(bytes(&result.output_data[0], 10), a);
}

TEST_F(execution, caller_callvalue)
{
    std::string s;
    s += "333401600052";  // CALLER CALLVALUE ADD MSTORE(0)
    s += "600a600af3";    // RETURN(10,10)
    evmc_message msg = {};
    msg.gas = 22;
    msg.sender.bytes[0] = 0xdd;
    msg.value.bytes[13] = 0xee;
    execute(msg, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 10);
    auto a = from_hex("0000ddee000000000000");
    EXPECT_EQ(bytes(&result.output_data[0], 10), a);
}

TEST_F(execution, code)
{
    // CODESIZE 2 0 CODECOPY RETURN(0,9)
    auto s = "38600260003960096000f3";
    execute(s);
    EXPECT_EQ(gas_used, 23);
    ASSERT_EQ(result.output_size, 9);
    auto a = from_hex({&s[4], 18});
    EXPECT_EQ(bytes(&result.output_data[0], 9), a);
}

TEST_F(execution, storage)
{
    std::string s;
    s += "60ff60ee55";    // CODESIZE 2 0 CODECOPY
    s += "60ee54600053";  // m[0] = ff
    s += "60016000f3";    // RETURN(0,1)
    execute(100000, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 99776 - 20000);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0xff);
}

TEST_F(execution, sstore_pop_stack)
{
    execute(100000, "60008060015560005360016000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, sload_cost_pre_tw)
{
    rev = EVMC_HOMESTEAD;
    execute(56, "60008054");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_NE(storage.find({}), storage.end());
}

TEST_F(execution, sstore_cost)
{
    auto v1 = evmc_bytes32{};
    v1.bytes[31] = 1;

    auto revs = {EVMC_BYZANTIUM, EVMC_CONSTANTINOPLE, EVMC_PETERSBURG};
    for (auto r : revs)
    {
        rev = r;
        storage_cold = true;

        // Added:
        storage.clear();
        execute(20006, PUSH(01) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage.clear();
        execute(20005, PUSH(01) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Deleted:
        storage.clear();
        storage[v1] = v1;
        execute(5006, PUSH(00) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage[v1] = v1;
        execute(5005, PUSH(00) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Modified:
        storage.clear();
        storage[v1] = v1;
        execute(5006, PUSH(02) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage[v1] = v1;
        execute(5005, PUSH(02) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Unchanged:
        storage.clear();
        storage[v1] = v1;
        execute(PUSH(01) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(gas_used, rev == EVMC_CONSTANTINOPLE ? 206 : 5006);
        execute(205, PUSH(01) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Added & unchanged:
        storage.clear();
        execute(PUSH(01) SSTORE(01) PUSH(01) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(gas_used, rev == EVMC_CONSTANTINOPLE ? 20212 : 25012);

        storage_cold = false;

        // Modified again:
        storage.clear();
        storage[v1] = v1;
        execute(PUSH(02) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(gas_used, rev == EVMC_CONSTANTINOPLE ? 206 : 5006);

        // Added & modified again:
        storage.clear();
        execute(PUSH(01) SSTORE(01) PUSH(02) SSTORE(01));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(gas_used, rev == EVMC_CONSTANTINOPLE ? 20212 : 25012);
    }
}

TEST_F(execution, tx_context)
{
    tx_context.block_timestamp = 0xdd;
    tx_context.block_coinbase.bytes[1] = 0xcc;
    tx_context.block_number = 0x1100;
    tx_context.block_difficulty.bytes[1] = 0xdd;
    tx_context.block_gas_limit = 0x990000;
    tx_context.tx_gas_price.bytes[2] = 0x66;
    tx_context.tx_origin.bytes[2] = 0x55;

    std::string s;
    s += "4241173a17";        // TIMESTAMP COINBASE OR GASPRICE OR
    s += "4317441745173217";  // NUMBER OR DIFFICULTY OR GASLIMIT OR ORIGIN OR
    s += "600052";            // m[0..] =
    s += "60206000f3";        // RETURN(0,32)
    execute(47, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[31], 0xdd);
    EXPECT_EQ(result.output_data[30], 0x11);
    EXPECT_EQ(result.output_data[29], 0x99);
    EXPECT_EQ(result.output_data[14], 0x55);
    EXPECT_EQ(result.output_data[13], 0xcc);
    EXPECT_EQ(result.output_data[2], 0x66);
    EXPECT_EQ(result.output_data[1], 0xdd);
}

TEST_F(execution, balance)
{
    std::string s;
    s += "3031";        // ADDRESS BALANCE
    s += "600053";      // m[0]
    s += "60016000f3";  // RETURN(0,1)
    balance = 7;
    execute(417, s);
    EXPECT_EQ(gas_used, 417);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 7);
}

TEST_F(execution, undefined)
{
    execute(1, "2a");
    EXPECT_EQ(result.status_code, EVMC_UNDEFINED_INSTRUCTION);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, invalid)
{
    execute(1, "fe");
    EXPECT_EQ(result.status_code, EVMC_INVALID_INSTRUCTION);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, log3)
{
    // TODO: Extend the test to all LOGs.
    std::string s;
    s += "60016002600360046077600253600280a3";  // 1 2 3 4 m[2] = 0x77 2 2 LOG3
    execute(s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 1546);
    ASSERT_EQ(log_data.size(), 2);
    EXPECT_EQ(log_data[0], 0x77);
    EXPECT_EQ(log_data[1], 0);
    EXPECT_EQ(log_topics.size(), 3);
    EXPECT_EQ(log_topics[0].bytes[31], 4);
    EXPECT_EQ(log_topics[1].bytes[31], 3);
    EXPECT_EQ(log_topics[2].bytes[31], 2);
}

TEST_F(execution, log_data_cost)
{
    for (auto op : {OP_LOG0, OP_LOG1, OP_LOG2, OP_LOG3, OP_LOG4})
    {
        auto num_topics = op - OP_LOG0;
        auto code = PUSH(00) _4x(DUP()) PUSH(01) PUSH(00) + hex(op);
        auto cost = 407 + num_topics * 375;
        execute(cost, code);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        execute(cost - 1, code);
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    }
}

TEST_F(execution, selfdestruct)
{
    rev = EVMC_SPURIOUS_DRAGON;
    execute("6009ff");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 5003);
    EXPECT_EQ(selfdestruct_beneficiary.bytes[19], 9);

    rev = EVMC_HOMESTEAD;
    execute("6007ff");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 3);
    EXPECT_EQ(selfdestruct_beneficiary.bytes[19], 7);

    rev = EVMC_TANGERINE_WHISTLE;
    execute("6008ff");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 30003);
    EXPECT_EQ(selfdestruct_beneficiary.bytes[19], 8);
}

TEST_F(execution, selfdestruct_with_balance)
{
    auto code = "6000ff";
    balance = 1;
    exists = false;

    rev = EVMC_TANGERINE_WHISTLE;
    execute(30003, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);

    execute(30002, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(result.gas_left, 0);

    rev = EVMC_HOMESTEAD;
    execute(3, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);

    exists = true;

    rev = EVMC_TANGERINE_WHISTLE;
    execute(5003, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);

    rev = EVMC_HOMESTEAD;
    execute(3, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
}

TEST_F(execution, sha3)
{
    execute("6108006103ff2060005260206000f3");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 738);
    ASSERT_EQ(result.output_size, 32);
    auto hash = from_hex("aeffb38c06e111d84216396baefeb7fed397f303d5cb84a33f1e8b485c4a22da");
    EXPECT_EQ(bytes(&result.output_data[0], 32), hash);
}

TEST_F(execution, blockhash)
{
    blockhash.bytes[13] = 0x13;

    tx_context.block_number = 0;
    auto code = "60004060005260206000f3";
    execute(code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 38);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[13], 0);

    tx_context.block_number = 257;
    execute(code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 38);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[13], 0);

    tx_context.block_number = 256;
    execute(code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 38);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[13], 0x13);
}

TEST_F(execution, extcode)
{
    extcode = {'a', 'b', 'c', 'd'};

    auto code = std::string{};
    code += "6002600003803b60019003";  // S = EXTCODESIZE(-2) - 1
    code += "90600080913c";            // EXTCODECOPY(-2, 0, 0, S)
    code += "60046000f3";              // RETURN(0, 4)

    execute(code);
    EXPECT_EQ(gas_used, 1445);
    ASSERT_EQ(result.output_size, 4);
    EXPECT_EQ(bytes_view(result.output_data, 3), bytes_view(extcode.data(), 3));
    EXPECT_EQ(result.output_data[3], 0);
    EXPECT_EQ(last_accessed_account.bytes[19], 0xfe);
}

TEST_F(execution, extcodehash)
{
    auto code = "60003f60005260206000f3";

    rev = EVMC_BYZANTIUM;
    execute(code);
    EXPECT_EQ(result.status_code, EVMC_UNDEFINED_INSTRUCTION);

    rev = EVMC_CONSTANTINOPLE;
    execute(code);
    EXPECT_EQ(gas_used, 418);
    ASSERT_EQ(result.output_size, 32);
    auto expected_hash = bytes(32, 0xee);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), expected_hash);
}

TEST_F(execution, delegatecall)
{
    auto code = std::string{};
    code += "6001600003600052";              // m[0] = 0xffffff...
    code += "600560046003600260016103e8f4";  // DELEGATECALL(1000, 0x01, ...)
    code += "60086000f3";

    auto call_output = bytes{0xa, 0xb, 0xc};
    call_result.output_data = call_output.data();
    call_result.output_size = call_output.size();
    call_result.gas_left = 1;

    execute(1700, code);

    EXPECT_EQ(gas_used, 1690);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    auto gas_left = 1700 - 736;
    EXPECT_EQ(call_msg.gas, gas_left - gas_left / 64);
    EXPECT_EQ(call_msg.input_size, 3);

    ASSERT_EQ(result.output_size, 8);
    auto output = bytes_view{result.output_data, result.output_size};
    EXPECT_EQ(output, (bytes{0xff, 0xff, 0xff, 0xff, 0xa, 0xb, 0xc, 0xff}));
}

TEST_F(execution, delegatecall_static)
{
    // Checks if DELEGATECALL forwards the "static" flag.
    msg.flags = EVMC_STATIC;
    execute("60008080808080f4");
    EXPECT_EQ(call_msg.gas, 0);
    EXPECT_EQ(call_msg.flags, EVMC_STATIC);
    EXPECT_EQ(gas_used, 718);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
}

TEST_F(execution, create)
{
    balance = 1;

    auto call_output = bytes{0xa, 0xb, 0xc};
    call_result.output_data = call_output.data();
    call_result.output_size = call_output.size();
    call_result.create_address.bytes[10] = 0xcc;
    call_result.gas_left = 200000;
    execute(300000, "602060006001f0600155");

    EXPECT_EQ(gas_used, 115816);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    auto key = evmc_bytes32{};
    key.bytes[31] = 1;
    EXPECT_EQ(storage[key].bytes[22], 0xcc);

    EXPECT_EQ(call_msg.input_size, 0x20);
}

TEST_F(execution, create_gas)
{
    for (auto r : {EVMC_HOMESTEAD, EVMC_TANGERINE_WHISTLE})
    {
        rev = r;
        execute(50000, "60008080f0");
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(gas_used, rev == EVMC_HOMESTEAD ? 50000 : 49719) << rev;
        EXPECT_EQ(call_msg.gas, rev == EVMC_HOMESTEAD ? 17991 : 17710) << rev;
    }
}

TEST_F(execution, create2)
{
    rev = EVMC_CONSTANTINOPLE;
    balance = 1;

    auto call_output = bytes{0xa, 0xb, 0xc};
    call_result.output_data = call_output.data();
    call_result.output_size = call_output.size();
    call_result.create_address.bytes[10] = 0xc2;
    call_result.gas_left = 200000;
    execute(300000, "605a604160006001f5600155");

    EXPECT_EQ(gas_used, 115817);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    EXPECT_EQ(call_msg.create2_salt.bytes[31], 0x5a);
    EXPECT_EQ(call_msg.gas, 263775);
    EXPECT_EQ(call_msg.kind, EVMC_CREATE2);

    auto key = evmc_bytes32{};
    key.bytes[31] = 1;
    EXPECT_EQ(storage[key].bytes[22], 0xc2);

    EXPECT_EQ(call_msg.input_size, 0x41);
}

TEST_F(execution, create2_salt_cost)
{
    rev = EVMC_CONSTANTINOPLE;
    auto code = "600060208180f5";

    call_msg.kind = EVMC_CALL;
    call_msg.depth = -1;
    execute(32021, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(call_msg.kind, EVMC_CREATE2);
    EXPECT_EQ(call_msg.depth, 1);

    call_msg.kind = EVMC_CALL;
    call_msg.depth = -1;
    execute(32021 - 1, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(call_msg.kind, EVMC_CALL);
    EXPECT_EQ(call_msg.depth, -1);
}

TEST_F(execution, create_balance_too_low)
{
    rev = EVMC_CONSTANTINOPLE;
    balance = 1;
    call_msg.kind = EVMC_CALL;
    for (auto op : {OP_CREATE, OP_CREATE2})
    {
        execute(PUSH(02) _3x(DUP()) + hex(op) + RETTOP());
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(std::count(result.output_data, result.output_data + result.output_size, 0), 32);
        EXPECT_EQ(call_msg.kind, EVMC_CALL);
    }
}

TEST_F(execution, create_failure)
{
    rev = EVMC_CONSTANTINOPLE;
    for (auto op : {OP_CREATE, OP_CREATE2})
    {
        call_msg.kind = EVMC_CALL;
        call_result.status_code = EVMC_FAILURE;
        execute(PUSH(00) _3x(DUP()) + hex(op) + RETTOP());
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(std::count(result.output_data, result.output_data + result.output_size, 0), 32);
        EXPECT_EQ(call_msg.kind, op == OP_CREATE ? EVMC_CREATE : EVMC_CREATE2);
    }
}

TEST_F(execution, call_failing_with_value)
{
    auto code = "60ff600060ff6000600160aa618000f150";

    call_msg.kind = EVMC_CREATE;

    execute(40000, code);
    EXPECT_EQ(gas_used, 32447);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(call_msg.kind, EVMC_CREATE);  // There was no call().

    execute(0x8000, code);
    EXPECT_EQ(gas_used, 0x8000);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(call_msg.kind, EVMC_CREATE);  // There was no call().
}

TEST_F(execution, call_with_value)
{
    auto code = "60ff600060ff6000600160aa618000f150";

    call_msg.kind = EVMC_CREATE;
    exists = true;
    balance = 1;
    call_result.gas_left = 1;

    execute(40000, code);
    EXPECT_EQ(gas_used, 7447 + 32082);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(call_msg.kind, EVMC_CALL);
    EXPECT_EQ(call_msg.depth, 1);
    EXPECT_EQ(call_msg.gas, 32083);
}

TEST_F(execution, call_with_value_depth_limit)
{
    exists = true;
    msg.depth = 1024;
    call_msg.kind = EVMC_CREATE2;
    execute("60ff600060ff6000600160aa618000f150");
    EXPECT_EQ(gas_used, 7447);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(call_msg.kind, EVMC_CREATE2);
    EXPECT_EQ(call_msg.depth, 0);
}

TEST_F(execution, call_depth_limit)
{
    rev = EVMC_CONSTANTINOPLE;
    msg.depth = 1024;

    auto code = PUSH(00) _6x(DUP());
    auto mark = 0xffe;

    for (auto op : {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL, OP_CREATE, OP_CREATE2})
    {
        call_msg.depth = mark;
        execute(code + hex(op));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(call_msg.depth, mark);
    }
}

TEST_F(execution, call_output)
{
    static bool result_is_correct = false;
    static uint8_t output[] = {0xa, 0xb};

    balance = 1;
    exists = true;
    call_result.output_data = output;
    call_result.output_size = sizeof(output);
    call_result.release = [](const evmc_result* result) {
        result_is_correct = result->output_size == sizeof(output) && result->output_data == output;
    };

    auto code_prefix_output_1 = PUSH(01) _6x(DUP()) "677fffffffffffffff";
    auto code_prefix_output_0 = PUSH(00) _6x(DUP()) "677fffffffffffffff";
    auto code_suffix = RETURN(03);

    for (auto op : {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL})
    {
        result_is_correct = false;
        execute(code_prefix_output_1 + hex(op) + code_suffix);
        EXPECT_TRUE(result_is_correct);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        ASSERT_EQ(result.output_size, 3);
        EXPECT_EQ(result.output_data[0], 0);
        EXPECT_EQ(result.output_data[1], 0xa);
        EXPECT_EQ(result.output_data[2], 0);


        result_is_correct = false;
        execute(code_prefix_output_0 + hex(op) + code_suffix);
        EXPECT_TRUE(result_is_correct);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        ASSERT_EQ(result.output_size, 3);
        EXPECT_EQ(result.output_data[0], 0);
        EXPECT_EQ(result.output_data[1], 0);
        EXPECT_EQ(result.output_data[2], 0);
    }
}

TEST_F(execution, call_high_gas)
{
    rev = EVMC_HOMESTEAD;
    exists = true;
    for (auto call_opcode : {"f1", "f2", "f4"})
    {
        execute(5000, "6000600060006000600060aa61134c"s + call_opcode);
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    }
}

TEST_F(execution, call_new_account_create)
{
    auto code = "6040600060406000600060aa611770f150";

    call_result.gas_left = 1000;
    execute(9000, code);
    EXPECT_EQ(gas_used, 729 + 5000);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(call_msg.kind, EVMC_CALL);
    EXPECT_EQ(call_msg.depth, 1);
    EXPECT_EQ(call_msg.gas, 6000);
}

TEST_F(execution, callcode_new_account_create)
{
    auto code = "60008080806001600061c350f250";

    balance = 1;
    call_result.gas_left = 1;
    execute(100000, code);
    EXPECT_EQ(gas_used, 59722);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(call_msg.kind, EVMC_CALLCODE);
    EXPECT_EQ(call_msg.depth, 1);
    EXPECT_EQ(call_msg.gas, 52300);
}

TEST_F(execution, call_then_oog)
{
    // Performs a CALL then execution OOG in the same code block.
    exists = true;
    call_result.status_code = EVMC_FAILURE;
    call_result.gas_left = 0;
    execute(1000, "6040600060406000600060aa60fef180018001800150");
    EXPECT_EQ(gas_used, 1000);
    EXPECT_EQ(call_msg.gas, 254);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, delegatecall_then_oog)
{
    // Performs a CALL then execution OOG in the same code block.
    exists = true;
    call_result.status_code = EVMC_FAILURE;
    call_result.gas_left = 0;
    execute(1000, "604060006040600060aa60fef4800180018001800150");
    EXPECT_EQ(gas_used, 1000);
    EXPECT_EQ(call_msg.gas, 254);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, staticcall_then_oog)
{
    // Performs a CALL then execution OOG in the same code block.
    exists = true;
    call_result.status_code = EVMC_FAILURE;
    call_result.gas_left = 0;
    execute(1000, "604060006040600060aa60fefa800180018001800150");
    EXPECT_EQ(gas_used, 1000);
    EXPECT_EQ(call_msg.gas, 254);
    EXPECT_EQ(result.gas_left, 0);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, revert)
{
    std::string s;
    s += "60ee8053";    // m[ee] == e
    s += "600260edfd";  // REVERT(ee,1)
    execute(s);
    EXPECT_EQ(gas_used, 39);
    EXPECT_EQ(result.status_code, EVMC_REVERT);
    ASSERT_EQ(result.output_size, 2);
    EXPECT_EQ(result.output_data[0], 0);
    EXPECT_EQ(result.output_data[1], 0xee);
}

TEST_F(execution, returndatasize_before_call)
{
    execute("3d60005360016000f3");
    EXPECT_EQ(gas_used, 17);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, returndatasize)
{
    uint8_t output[13];
    call_result.output_size = std::size(output);
    call_result.output_data = std::begin(output);

    auto code = "60008080808080f43d60005360016000f3";
    execute(code);
    EXPECT_EQ(gas_used, 735);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], std::size(output));

    call_result.output_size = 1;
    call_result.status_code = EVMC_FAILURE;
    execute(code);
    EXPECT_EQ(gas_used, 735);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    call_result.output_size = 0;
    call_result.status_code = EVMC_INTERNAL_ERROR;
    execute(code);
    EXPECT_EQ(gas_used, 735);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, returndatacopy)
{
    uint8_t output[32] = {1, 2, 3, 4, 5, 6, 7};
    call_result.output_size = std::size(output);
    call_result.output_data = std::begin(output);

    auto code = "600080808060aa60fff4506020600060003e60206000f3";
    execute(code);
    EXPECT_EQ(gas_used, 999);
    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(result.output_data[0], 1);
    EXPECT_EQ(result.output_data[1], 2);
    EXPECT_EQ(result.output_data[2], 3);
    EXPECT_EQ(result.output_data[6], 7);
    EXPECT_EQ(result.output_data[7], 0);
}

TEST_F(execution, returndatacopy_empty)
{
    auto code = "600080808060aa60fff4600080803e60016000f3";
    execute(code);
    EXPECT_EQ(gas_used, 994);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, returndatacopy_cost)
{
    auto output = uint8_t{};
    call_result.output_data = &output;
    call_result.output_size = sizeof(output);
    auto code = "60008080808080fa6001600060003e";
    execute(736, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(735, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, returndatacopy_outofrange)
{
    auto output = uint8_t{};
    call_result.output_data = &output;
    call_result.output_size = sizeof(output);
    execute(735, "60008080808080fa6002600060003e");
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

    execute(735, "60008080808080fa6001600160003e");
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

    execute(735, "60008080808080fa6000600260003e");
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);
}

TEST_F(execution, shl)
{
    auto code = "600560011b6000526001601ff3";
    rev = EVMC_CONSTANTINOPLE;
    execute(code);
    EXPECT_EQ(gas_used, 24);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 5 << 1);
}

TEST_F(execution, shr)
{
    auto code = "600560011c6000526001601ff3";
    rev = EVMC_CONSTANTINOPLE;
    execute(code);
    EXPECT_EQ(gas_used, 24);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 5 >> 1);
}

TEST_F(execution, sar)
{
    auto code = "600160000360021d60005260016000f3";
    rev = EVMC_CONSTANTINOPLE;
    execute(code);
    EXPECT_EQ(gas_used, 30);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0xff);  // MSB of (-1 >> 2) == -1
}

TEST_F(execution, sar_01)
{
    auto code = "600060011d60005260016000f3";
    rev = EVMC_CONSTANTINOPLE;
    execute(code);
    EXPECT_EQ(gas_used, 24);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);
}

TEST_F(execution, shift_overflow)
{
    rev = EVMC_CONSTANTINOPLE;
    auto code_prefix = NOT(00) PUSH2(0100);
    auto code_suffix = RETTOP();

    for (auto op : {OP_SHL, OP_SHR, OP_SAR})
    {
        execute(code_prefix + hex(op) + code_suffix);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        ASSERT_EQ(result.output_size, 32);
        auto a = std::accumulate(result.output_data, result.output_data + result.output_size, 0);
        EXPECT_EQ(a, op == OP_SAR ? 32 * 0xff : 0);
    }
}

TEST_F(execution, undefined_instructions)
{
    for (auto r = 0; r <= EVMC_MAX_REVISION; ++r)
    {
        auto rev = evmc_revision(r);
        auto names = evmc_get_instruction_names_table(rev);
        auto msg = evmc_message{};

        for (uint8_t opcode = 0; opcode <= 0xfe; ++opcode)
        {
            if (names[opcode] != nullptr)
                continue;

            auto result = vm->execute(vm, this, rev, &msg, &opcode, sizeof(opcode));
            EXPECT_EQ(result.status_code, EVMC_UNDEFINED_INSTRUCTION) << std::hex << opcode;
            EXPECT_FALSE(result.release);
        }
    }
}

TEST_F(execution, abort)
{
    for (auto r = 0; r <= EVMC_MAX_REVISION; ++r)
    {
        auto rev = evmc_revision(r);
        auto opcode = uint8_t{0xfe};
        auto msg = evmc_message{};
        auto result = vm->execute(vm, this, rev, &msg, &opcode, sizeof(opcode));
        EXPECT_EQ(result.status_code, EVMC_INVALID_INSTRUCTION);
        EXPECT_FALSE(result.release);
    }
}

TEST_F(execution, staticmode)
{
    auto code_prefix = std::string{PUSH(01) _6x(DUP())};

    rev = EVMC_CONSTANTINOPLE;
    for (auto op : {OP_SSTORE, OP_LOG0, OP_LOG1, OP_LOG2, OP_LOG3, OP_LOG4, OP_CALL, OP_CREATE,
             OP_CREATE2, OP_SELFDESTRUCT})
    {
        msg.flags |= EVMC_STATIC;
        execute(code_prefix + hex(op));
        EXPECT_EQ(result.status_code, EVMC_STATIC_MODE_VIOLATION) << hex(op);
        EXPECT_EQ(result.gas_left, 0);
    }
}

TEST_F(execution, mstore8_memory_cost)
{
    auto code = PUSH(00) MSTORE8(00);
    execute(12, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(11, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, sha3_memory_cost)
{
    auto code = SHA3(00, 01);
    execute(45, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(44, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, calldatacopy_memory_cost)
{
    auto code = PUSH(01) PUSH(00) PUSH(00) "37";
    execute(18, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(17, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, codecopy_memory_cost)
{
    auto code = PUSH(01) PUSH(00) PUSH(00) "39";
    execute(18, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(17, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_F(execution, extcodecopy_memory_cost)
{
    auto code = PUSH(01) PUSH(00) _2x(DUP()) "3c";
    execute(718, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(717, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

struct memory_access_opcode
{
    evmc_opcode opcode;
    int memory_index_arg;
    int memory_size_arg;
};

struct memory_access_params
{
    uint64_t index;
    uint64_t size;
};

memory_access_opcode memory_access_opcodes[] = {
    {OP_SHA3, 0, 1},
    {OP_CALLDATACOPY, 0, 2},
    {OP_CODECOPY, 0, 2},
    {OP_MLOAD, 0, -1},
    {OP_MSTORE, 0, -1},
    {OP_MSTORE8, 0, -1},
    {OP_EXTCODECOPY, 1, 3},
    {OP_RETURNDATACOPY, 0, 2},
    {OP_LOG0, 0, 1},
    {OP_LOG1, 0, 1},
    {OP_LOG2, 0, 1},
    {OP_LOG3, 0, 1},
    {OP_LOG4, 0, 1},
    {OP_RETURN, 0, 1},
    {OP_REVERT, 0, 1},
    {OP_CALL, 3, 4},
    {OP_CALL, 5, 6},
    {OP_CALLCODE, 3, 4},
    {OP_CALLCODE, 5, 6},
    {OP_DELEGATECALL, 2, 3},
    {OP_DELEGATECALL, 4, 5},
    {OP_STATICCALL, 2, 3},
    {OP_STATICCALL, 4, 5},
    {OP_CREATE, 1, 2},
    {OP_CREATE2, 1, 2},
};

memory_access_params memory_access_test_cases[] = {
    {0, 0x100000000},
    {0x100000000, 0},
    {0x100000000, 1},
    {0x100000000, 0x100000000},
};

TEST_F(execution, memory_access)
{
    rev = EVMC_CONSTANTINOPLE;
    auto metrics = evmc_get_instruction_metrics_table(rev);

    for (auto& p : memory_access_test_cases)
    {
        auto ss = std::ostringstream{};
        ss << std::hex << std::setw(10) << std::setfill('0') << p.size;
        const auto push_size = "64" + ss.str();
        ss.str({});
        ss << std::hex << std::setw(10) << std::setfill('0') << p.index;
        const auto push_index = "64" + ss.str();

        for (auto& t : memory_access_opcodes)
        {
            const int num_args = metrics[t.opcode].num_stack_arguments;
            auto h = std::max(num_args, t.memory_size_arg + 1);
            auto code = std::string{};

            if (t.memory_size_arg >= 0)
            {
                while (--h != t.memory_size_arg)
                    code += PUSH(00);

                code += push_size;
            }
            else if (p.index == 0 || p.size == 0)
                continue;  // Skip opcodes not having SIZE argument.

            while (--h != t.memory_index_arg)
                code += PUSH(00);

            code += push_index;

            while (h-- != 0)
                code += PUSH(00);

            code += hex(t.opcode);

            execute(code);
            if (p.size == 0)
            {
                EXPECT_EQ(result.status_code, (t.opcode == OP_REVERT) ? EVMC_REVERT : EVMC_SUCCESS);
                EXPECT_NE(result.gas_left, 0);
            }
            else
            {
                EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
                EXPECT_EQ(result.gas_left, 0);
            }
        }
    }
}