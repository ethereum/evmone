// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "utils.hpp"

#include <evmone/evmone.h>

#include <evmc/helpers.hpp>
#include <gtest/gtest.h>
#include <map>

extern evmc_host_interface interface;

class execution : public testing::Test, public evmc_context
{
protected:
    evmc_instance* vm = nullptr;
    evmc_revision rev = EVMC_BYZANTIUM;  // Use Byzantium by default.
    evmc_result result = {};
    int64_t gas_used = 0;

    std::unordered_map<evmc_bytes32, evmc_bytes32> storage;

    evmc_tx_context tx_context = {};

    bytes log_data;
    std::vector<evmc_bytes32> log_topics;

    evmc_address selfdestruct_beneficiary = {};

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
        auto input = from_hex(input_hex.data());
        auto msg = evmc_message{};
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


inline bool is_zero(const evmc_bytes32& v) noexcept
{
    return v == evmc_bytes32{};
}

evmc_host_interface execution::interface = {
    nullptr,
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key) {
        return static_cast<execution*>(ctx)->storage[*key];
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key, const evmc_bytes32* value) {
        auto& storage = static_cast<execution*>(ctx)->storage[*key];

        if (storage == *value)
            return EVMC_STORAGE_UNCHANGED;

        evmc_storage_status status = EVMC_STORAGE_MODIFIED;
        if (is_zero(storage) && !is_zero(*value))
            status = EVMC_STORAGE_ADDED;
        else if (!is_zero(storage) && is_zero(*value))
            status = EVMC_STORAGE_DELETED;
        else if (!is_zero(storage))
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        storage = *value;

        return status;
    },
    [](evmc_context*, const evmc_address*) {
        evmc_uint256be balance = {};
        balance.bytes[31] = 7;
        return balance;
    },
    nullptr,
    nullptr,
    nullptr,
    [](evmc_context* ctx, const evmc_address*, const evmc_address* beneficiary) {
        static_cast<execution*>(ctx)->selfdestruct_beneficiary = *beneficiary;
    },
    nullptr,
    [](evmc_context* ctx) { return static_cast<execution*>(ctx)->tx_context; },
    nullptr,
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

TEST_F(execution, jumpi_at_the_end)
{
    execute(1000, "5b6001600057");
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
    EXPECT_EQ(gas_used, 1000);
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
    s += "60056000f3";  // RETURN(0,5)
    execute(57, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);
    ASSERT_EQ(result.output_size, 5);
    EXPECT_EQ(result.output_data[0], 0);
    EXPECT_EQ(result.output_data[2], 0xaa);
    EXPECT_EQ(result.output_data[4], 0xdd);
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
    execute(417, s);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(result.gas_left, 0);  // FIXME: Implement storage gas calculation.
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

TEST_F(execution, selfdestruct)
{
    execute("6009ff");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 5003);
    EXPECT_EQ(selfdestruct_beneficiary.bytes[19], 9);

    rev = EVMC_HOMESTEAD;
    execute("6007ff");
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(gas_used, 3);
    EXPECT_EQ(selfdestruct_beneficiary.bytes[19], 7);
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
