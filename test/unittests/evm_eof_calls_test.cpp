// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"
#include "test/utils/bytecode.hpp"

using evmone::test::evm;
using namespace evmc::literals;

inline constexpr auto max_uint256 =
    0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32;

TEST_P(evm, eof1_delegatecall2_eof1)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.accounts[callee].code = eof_bytecode(OP_STOP);
    bytes call_output{0x01, 0x02, 0x03};
    host.call_result.output_data = std::data(call_output);
    host.call_result.output_size = std::size(call_output);
    host.call_result.gas_left = 100;
    host.call_result.status_code = EVMC_SUCCESS;

    const auto code = eof_bytecode(delegatecall2(callee) + OP_RETURNDATASIZE + OP_PUSH0 + OP_PUSH0 +
                                       OP_RETURNDATACOPY + ret(0, evmone::OP_RETURNDATASIZE),
        4);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "010203");
}

TEST_P(evm, eof1_delegatecall2_legacy)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);

    for (const auto& target_code : {""_hex, "EF"_hex, "EF01"_hex, "000000"_hex})
    {
        SCOPED_TRACE("target code: " + hex(target_code));
        host.accounts[callee].code = target_code;

        const auto code = eof_bytecode(delegatecall2(callee) + ret_top(), 3);

        execute(code);
        EXPECT_GAS_USED(EVMC_SUCCESS, 124);  // Low gas usage because DELEGATECALL2 fails lightly.
        EXPECT_OUTPUT_INT(0);
    }
}


TEST_P(evm, delegatecall2)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee].code = "EF00"_hex;

    auto code =
        eof_bytecode(mstore(0, push(1) + push0() + OP_SUB) + delegatecall2(callee).input(0x2, 0x3) +
                         returndatacopy(0x4, 0x0, 0x5) + ret(0, 8),
            4);

    auto call_output = bytes{0xa, 0xb, 0xc, 0xd, 0xe};
    host.call_result.output_data = call_output.data();
    host.call_result.output_size = call_output.size();
    host.call_result.gas_left = 1;

    msg.value.bytes[17] = 0xfe;

    execute(1700, code);

    auto gas_before_call = 3 + 2 + 3 + 3 + 6 + 3 + 3 + 3 + 100;
    auto gas_left = 1700 - gas_before_call;
    ASSERT_EQ(host.recorded_calls.size(), 1);
    const auto& call_msg = host.recorded_calls.back();
    EXPECT_EQ(call_msg.gas, gas_left - gas_left / 64);
    EXPECT_EQ(call_msg.input_size, 3);
    EXPECT_EQ(call_msg.value.bytes[17], 0xfe);

    ASSERT_EQ(result.output_size, 8);
    EXPECT_EQ(output, (bytes{0xff, 0xff, 0xff, 0xff, 0xa, 0xb, 0xc, 0xd}));

    EXPECT_GAS_USED(EVMC_SUCCESS,
        gas_before_call + call_msg.gas - host.call_result.gas_left + 3 + 3 + 3 + 3 + 3 + 3 + 3);
}

TEST_P(evm, delegatecall2_static)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee].code = "EF00"_hex;

    // Checks if DELEGATECALL2 forwards the "static" flag.
    msg.flags = EVMC_STATIC;
    execute(1000, eof_bytecode(delegatecall2(callee) + OP_STOP, 3));
    ASSERT_EQ(host.recorded_calls.size(), 1);
    const auto& call_msg = host.recorded_calls.back();
    auto gas_before_call = 3 + 3 + 3 + 100;
    auto gas_left = 1000 - gas_before_call;
    EXPECT_EQ(call_msg.gas, gas_left - gas_left / 64);
    EXPECT_EQ(call_msg.flags, uint32_t{EVMC_STATIC});
    EXPECT_GAS_USED(EVMC_SUCCESS, gas_before_call + call_msg.gas);
}

TEST_P(evm, delegatecall2_oog_depth_limit)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee].code = "EF00"_hex;

    msg.depth = 1024;
    const auto code = eof_bytecode(delegatecall2(callee) + ret_top(), 3);

    execute(1000, code);
    EXPECT_EQ(host.recorded_calls.size(), 0);
    auto expected_gas_used = 3 + 3 + 3 + 100 + 3 + 3 + 3 + 3 + 3;
    EXPECT_GAS_USED(EVMC_SUCCESS, expected_gas_used);
    EXPECT_OUTPUT_INT(0);

    execute(expected_gas_used, code);
    // Different from DELEGATECALL, we can't require a minimum gas for the call
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, call2_failing_with_value)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee] = {};

    const auto code = eof_bytecode(call2(callee).input(0x0, 0xff).value(0x1) + OP_STOP, 4);

    // Fails on balance check.
    execute(12000, code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 4 * 3 + 100 + 8 * 3 + 9000);
    EXPECT_EQ(host.recorded_calls.size(), 0);  // There was no call().

    // Fails on value transfer additional cost - minimum gas limit that triggers this
    execute(4 * 3 + 100 + 8 * 3, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_EQ(host.recorded_calls.size(), 0);  // There was no call().

    // Fails on value transfer additional cost - maximum gas limit that triggers this
    execute(4 * 3 + 100 + 8 * 3 + 9000 - 1, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_EQ(host.recorded_calls.size(), 0);  // There was no call().
}

TEST_P(evm, call2_with_value)
{
    rev = EVMC_PRAGUE;

    constexpr auto call_sender = 0x5e4d00000000000000000000000000000000d4e5_address;
    constexpr auto call_dst = 0x00000000000000000000000000000000000000aa_address;

    const auto code = eof_bytecode(call2(call_dst).input(0x0, 0xff).value(0x1) + OP_STOP, 4);

    msg.recipient = call_sender;
    host.accounts[msg.recipient].set_balance(1);
    host.accounts[call_dst] = {};
    host.call_result.gas_left = 1;

    execute(40000, code);

    auto gas_before_call = 4 * 3 + 2600 + 8 * 3 + 9000;
    ASSERT_EQ(host.recorded_calls.size(), 1);
    const auto& call_msg = host.recorded_calls.back();
    EXPECT_EQ(call_msg.kind, EVMC_CALL);
    EXPECT_EQ(call_msg.depth, 1);
    auto gas_left = 40000 - gas_before_call;
    EXPECT_EQ(call_msg.gas, gas_left - gas_left / 64);
    EXPECT_EQ(call_msg.recipient, call_dst);
    EXPECT_EQ(call_msg.sender, call_sender);

    EXPECT_GAS_USED(EVMC_SUCCESS, gas_before_call + call_msg.gas - host.call_result.gas_left);
}

TEST_P(evm, call2_with_value_depth_limit)
{
    rev = EVMC_PRAGUE;

    constexpr auto call_dst = 0x00000000000000000000000000000000000000aa_address;
    host.accounts[call_dst] = {};

    msg.depth = 1024;
    execute(eof_bytecode(call2(call_dst).input(0x0, 0xff).value(0x1) + OP_STOP, 4));

    EXPECT_EQ(gas_used, 4 * 3 + 2600 + 8 * 3 + 9000);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_EQ(host.recorded_calls.size(), 0);
}

TEST_P(evm, call2_depth_limit)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee].code = "EF00"_hex;
    msg.depth = 1024;

    for (auto op : {OP_CALL2, OP_DELEGATECALL2, OP_STATICCALL2})
    {
        const auto code = eof_bytecode(push(callee) + 3 * push0() + op + ret_top(), 4);
        execute(code);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        EXPECT_EQ(host.recorded_calls.size(), 0);
        EXPECT_OUTPUT_INT(0);
    }
}

TEST_P(evm, call2_output)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);
    host.accounts[callee].code = "EF00"_hex;

    static bool result_is_correct = false;
    static uint8_t call_output[] = {0xa, 0xb};

    host.accounts[{}].set_balance(1);
    host.call_result.output_data = call_output;
    host.call_result.output_size = sizeof(call_output);
    host.call_result.release = [](const evmc_result* r) {
        result_is_correct = r->output_size == sizeof(call_output) && r->output_data == call_output;
    };

    auto code_prefix = 3 * push0() + push(callee);
    auto code_suffix_output_0 = returndatacopy(0, 0, 0) + ret(0, 3);
    auto code_suffix_output_1 = returndatacopy(1, 0, 1) + ret(0, 3);

    for (auto op : {OP_CALL2, OP_DELEGATECALL2, OP_STATICCALL2})
    {
        result_is_correct = false;
        const uint16_t max_stack = 4 + (op == OP_CALL2 ? 0 : 1);
        execute(eof_bytecode(code_prefix + hex(op) + code_suffix_output_1, max_stack));
        EXPECT_TRUE(result_is_correct);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        ASSERT_EQ(result.output_size, 3);
        EXPECT_EQ(result.output_data[0], 0);
        EXPECT_EQ(result.output_data[1], 0xa);
        EXPECT_EQ(result.output_data[2], 0);


        result_is_correct = false;
        execute(eof_bytecode(code_prefix + hex(op) + code_suffix_output_0, max_stack));
        EXPECT_TRUE(result_is_correct);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        ASSERT_EQ(result.output_size, 3);
        EXPECT_EQ(result.output_data[0], 0);
        EXPECT_EQ(result.output_data[1], 0);
        EXPECT_EQ(result.output_data[2], 0);
    }
}

TEST_P(evm, call2_value_zero_to_nonexistent_account)
{
    constexpr auto call_gas = 6000;
    host.call_result.gas_left = 1000;

    const auto code = push(0x40) + push(0) + push(0x40) + push(0) + push(0) + push(0xaa) +
                      push(call_gas) + OP_CALL2 + OP_POP;

    execute(9000, code);
    EXPECT_EQ(gas_used, 729 + (call_gas - host.call_result.gas_left));
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    ASSERT_EQ(host.recorded_calls.size(), 1);
    const auto& call_msg = host.recorded_calls.back();
    EXPECT_EQ(call_msg.kind, EVMC_CALL);
    EXPECT_EQ(call_msg.depth, 1);
    EXPECT_EQ(call_msg.gas, 6000);
    EXPECT_EQ(call_msg.input_size, 64);
    EXPECT_EQ(call_msg.recipient, 0x00000000000000000000000000000000000000aa_address);
    EXPECT_EQ(call_msg.value.bytes[31], 0);
}

// TEST_P(evm, call_new_account_creation_cost)
// {
//     constexpr auto call_dst = 0x00000000000000000000000000000000000000ad_address;
//     constexpr auto msg_dst = 0x0000000000000000000000000000000000000003_address;
//     const auto code =
//         4 * push(0) + calldataload(0) + push(call_dst) + push(0) + OP_CALL + ret_top();
//     msg.recipient = msg_dst;


//     rev = EVMC_TANGERINE_WHISTLE;
//     host.accounts[msg.recipient].set_balance(0);
//     execute(code, "00"_hex);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 25000 + 739);
//     EXPECT_OUTPUT_INT(1);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     EXPECT_EQ(host.recorded_calls.back().recipient, call_dst);
//     EXPECT_EQ(host.recorded_calls.back().gas, 0);
//     ASSERT_EQ(host.recorded_account_accesses.size(), 2);
//     EXPECT_EQ(host.recorded_account_accesses[0], call_dst);  // Account exist?
//     EXPECT_EQ(host.recorded_account_accesses[1], call_dst);  // Call.
//     host.recorded_account_accesses.clear();
//     host.recorded_calls.clear();

//     rev = EVMC_TANGERINE_WHISTLE;
//     host.accounts[msg.recipient].set_balance(1);
//     execute(code, "0000000000000000000000000000000000000000000000000000000000000001"_hex);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 25000 + 9000 + 739);
//     EXPECT_OUTPUT_INT(1);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     EXPECT_EQ(host.recorded_calls.back().recipient, call_dst);
//     EXPECT_EQ(host.recorded_calls.back().gas, 2300);
//     EXPECT_EQ(host.recorded_calls.back().sender, msg_dst);
//     EXPECT_EQ(host.recorded_calls.back().value.bytes[31], 1);
//     EXPECT_EQ(host.recorded_calls.back().input_size, 0);
//     ASSERT_EQ(host.recorded_account_accesses.size(), 3);
//     EXPECT_EQ(host.recorded_account_accesses[0], call_dst);       // Account exist?
//     EXPECT_EQ(host.recorded_account_accesses[1], msg.recipient);  // Balance.
//     EXPECT_EQ(host.recorded_account_accesses[2], call_dst);       // Call.
//     host.recorded_account_accesses.clear();
//     host.recorded_calls.clear();

//     rev = EVMC_SPURIOUS_DRAGON;
//     host.accounts[msg.recipient].set_balance(0);
//     execute(code, "00"_hex);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 739);
//     EXPECT_OUTPUT_INT(1);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     EXPECT_EQ(host.recorded_calls.back().recipient, call_dst);
//     EXPECT_EQ(host.recorded_calls.back().gas, 0);
//     EXPECT_EQ(host.recorded_calls.back().sender, msg_dst);
//     EXPECT_EQ(host.recorded_calls.back().value.bytes[31], 0);
//     EXPECT_EQ(host.recorded_calls.back().input_size, 0);
//     ASSERT_EQ(host.recorded_account_accesses.size(), 1);
//     EXPECT_EQ(host.recorded_account_accesses[0], call_dst);  // Call.
//     host.recorded_account_accesses.clear();
//     host.recorded_calls.clear();

//     rev = EVMC_SPURIOUS_DRAGON;
//     host.accounts[msg.recipient].set_balance(1);
//     execute(code, "0000000000000000000000000000000000000000000000000000000000000001"_hex);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 25000 + 9000 + 739);
//     EXPECT_OUTPUT_INT(1);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     EXPECT_EQ(host.recorded_calls.back().recipient, call_dst);
//     EXPECT_EQ(host.recorded_calls.back().gas, 2300);
//     EXPECT_EQ(host.recorded_calls.back().sender, msg_dst);
//     EXPECT_EQ(host.recorded_calls.back().value.bytes[31], 1);
//     EXPECT_EQ(host.recorded_calls.back().input_size, 0);
//     ASSERT_EQ(host.recorded_account_accesses.size(), 3);
//     EXPECT_EQ(host.recorded_account_accesses[0], call_dst);       // Account exist?
//     EXPECT_EQ(host.recorded_account_accesses[1], msg.recipient);  // Balance.
//     EXPECT_EQ(host.recorded_account_accesses[2], call_dst);       // Call.
//     host.recorded_account_accesses.clear();
//     host.recorded_calls.clear();
// }

// TEST_P(evm, callcode_new_account_create)
// {
//     constexpr auto code = "60008080806001600061c350f250";
//     constexpr auto call_sender = 0x5e4d00000000000000000000000000000000d4e5_address;

//     msg.recipient = call_sender;
//     host.accounts[msg.recipient].set_balance(1);
//     host.call_result.gas_left = 1;
//     execute(100000, code);
//     EXPECT_EQ(gas_used, 59722);
//     EXPECT_EQ(result.status_code, EVMC_SUCCESS);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.kind, EVMC_CALLCODE);
//     EXPECT_EQ(call_msg.depth, 1);
//     EXPECT_EQ(call_msg.gas, 52300);
//     EXPECT_EQ(call_msg.sender, call_sender);
//     EXPECT_EQ(call_msg.value.bytes[31], 1);
// }

// TEST_P(evm, call_then_oog)
// {
//     // Performs a CALL then OOG in the same code block.
//     auto call_dst = evmc_address{};
//     call_dst.bytes[19] = 0xaa;
//     host.accounts[call_dst] = {};
//     host.call_result.status_code = EVMC_FAILURE;
//     host.call_result.gas_left = 0;

//     const auto code =
//         call(0xaa).gas(254).value(0).input(0, 0x40).output(0, 0x40) + 4 * add(OP_DUP1) + OP_POP;

//     execute(1000, code);
//     EXPECT_EQ(gas_used, 1000);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.gas, 254);
//     EXPECT_EQ(result.gas_left, 0);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
// }

// TEST_P(evm, callcode_then_oog)
// {
//     // Performs a CALLCODE then OOG in the same code block.
//     host.call_result.status_code = EVMC_FAILURE;
//     host.call_result.gas_left = 0;

//     const auto code =
//         callcode(0xaa).gas(100).value(0).input(0, 3).output(3, 9) + 4 * add(OP_DUP1) + OP_POP;

//     execute(825, code);
//     EXPECT_STATUS(EVMC_OUT_OF_GAS);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.gas, 100);
// }

// TEST_P(evm, delegatecall_then_oog)
// {
//     // Performs a CALL then OOG in the same code block.
//     auto call_dst = evmc_address{};
//     call_dst.bytes[19] = 0xaa;
//     host.accounts[call_dst] = {};
//     host.call_result.status_code = EVMC_FAILURE;
//     host.call_result.gas_left = 0;

//     const auto code =
//         delegatecall(0xaa).gas(254).input(0, 0x40).output(0, 0x40) + 4 * add(OP_DUP1) + OP_POP;

//     execute(1000, code);
//     EXPECT_EQ(gas_used, 1000);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.gas, 254);
//     EXPECT_EQ(result.gas_left, 0);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
// }

// TEST_P(evm, staticcall_then_oog)
// {
//     // Performs a STATICCALL then OOG in the same code block.
//     auto call_dst = evmc_address{};
//     call_dst.bytes[19] = 0xaa;
//     host.accounts[call_dst] = {};
//     host.call_result.status_code = EVMC_FAILURE;
//     host.call_result.gas_left = 0;

//     const auto code =
//         staticcall(0xaa).gas(254).input(0, 0x40).output(0, 0x40) + 4 * add(OP_DUP1) + OP_POP;

//     execute(1000, code);
//     EXPECT_EQ(gas_used, 1000);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.gas, 254);
//     EXPECT_EQ(result.gas_left, 0);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
// }

// TEST_P(evm, staticcall_input)
// {
//     const auto code = mstore(3, 0x010203) + staticcall(0).gas(0xee).input(32, 3);
//     execute(code);
//     ASSERT_EQ(host.recorded_calls.size(), 1);
//     const auto& call_msg = host.recorded_calls.back();
//     EXPECT_EQ(call_msg.gas, 0xee);
//     EXPECT_EQ(call_msg.input_size, 3);
//     EXPECT_EQ(hex(bytes_view(call_msg.input_data, call_msg.input_size)), "010203");
// }

// TEST_P(evm, call_with_value_low_gas)
// {
//     // Create the call destination account.
//     host.accounts[0x0000000000000000000000000000000000000000_address] = {};
//     for (auto call_op : {OP_CALL, OP_CALLCODE})
//     {
//         auto code = 4 * push(0) + push(1) + 2 * push(0) + call_op + OP_POP;
//         execute(9721, code);
//         EXPECT_EQ(result.status_code, EVMC_SUCCESS);
//         EXPECT_EQ(result.gas_left, 2300 - 2);
//     }
// }

// TEST_P(evm, call_oog_after_balance_check)
// {
//     // Create the call destination account.
//     host.accounts[0x0000000000000000000000000000000000000000_address] = {};
//     for (auto op : {OP_CALL, OP_CALLCODE})
//     {
//         auto code = 4 * push(0) + push(1) + 2 * push(0) + op + OP_SELFDESTRUCT;
//         execute(12420, code);
//         EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
//     }
// }

// TEST_P(evm, call_oog_after_depth_check)
// {
//     // Create the call recipient account.
//     host.accounts[0x0000000000000000000000000000000000000000_address] = {};
//     msg.depth = 1024;

//     for (auto op : {OP_CALL, OP_CALLCODE})
//     {
//         const auto code = 4 * push(0) + push(1) + 2 * push(0) + op + OP_SELFDESTRUCT;
//         execute(12420, code);
//         EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
//     }

//     rev = EVMC_TANGERINE_WHISTLE;
//     const auto code = 7 * push(0) + OP_CALL + OP_SELFDESTRUCT;
//     execute(721, code);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

//     execute(721 + 5000 - 1, code);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
// }

// TEST_P(evm, call_recipient_and_code_address)
// {
//     constexpr auto origin = 0x9900000000000000000000000000000000000099_address;
//     constexpr auto executor = 0xee000000000000000000000000000000000000ee_address;
//     constexpr auto recipient = 0x4400000000000000000000000000000000000044_address;

//     msg.sender = origin;
//     msg.recipient = executor;

//     for (auto op : {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL})
//     {
//         const auto code = 5 * push(0) + push(recipient) + push(0) + op;
//         execute(100000, code);
//         EXPECT_GAS_USED(EVMC_SUCCESS, 721);
//         ASSERT_EQ(host.recorded_calls.size(), 1);
//         const auto& call = host.recorded_calls[0];
//         EXPECT_EQ(call.recipient, (op == OP_CALL || op == OP_STATICCALL) ? recipient : executor);
//         EXPECT_EQ(call.code_address, recipient);
//         EXPECT_EQ(call.sender, (op == OP_DELEGATECALL) ? origin : executor);
//         host.recorded_calls.clear();
//     }
// }

// TEST_P(evm, call_value)
// {
//     constexpr auto origin = 0x9900000000000000000000000000000000000099_address;
//     constexpr auto executor = 0xee000000000000000000000000000000000000ee_address;
//     constexpr auto recipient = 0x4400000000000000000000000000000000000044_address;

//     constexpr auto passed_value = 3;
//     constexpr auto origin_value = 8;

//     msg.sender = origin;
//     msg.recipient = executor;
//     msg.value.bytes[31] = origin_value;
//     host.accounts[executor].set_balance(passed_value);
//     host.accounts[recipient] = {};  // Create the call recipient account.

//     for (auto op : {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL})
//     {
//         const auto has_value_arg = (op == OP_CALL || op == OP_CALLCODE);
//         const auto value_cost = has_value_arg ? 9000 : 0;
//         const auto expected_value = has_value_arg           ? passed_value :
//                                     (op == OP_DELEGATECALL) ? origin_value :
//                                                               0;

//         const auto code =
//             4 * push(0) + push(has_value_arg ? passed_value : 0) + push(recipient) + push(0) +
//             op;
//         execute(100000, code);
//         EXPECT_GAS_USED(EVMC_SUCCESS, 721 + value_cost);
//         ASSERT_EQ(host.recorded_calls.size(), 1);
//         const auto& call = host.recorded_calls[0];
//         EXPECT_EQ(call.value.bytes[31], expected_value) << op;
//         host.recorded_calls.clear();
//     }
// }

// TEST_P(evm, create_oog_after)
// {
//     rev = EVMC_CONSTANTINOPLE;
//     for (auto op : {OP_CREATE, OP_CREATE2})
//     {
//         auto code = 4 * push(0) + op + OP_SELFDESTRUCT;
//         execute(39000, code);
//         EXPECT_STATUS(EVMC_OUT_OF_GAS);
//     }
// }

// TEST_P(evm, returndatasize_before_call)
// {
//     execute(returndatasize() + ret_top());
//     EXPECT_GAS_USED(EVMC_SUCCESS, 17);
//     EXPECT_OUTPUT_INT(0);
// }

// TEST_P(evm, returndatasize)
// {
//     const uint8_t call_output[13]{};
//     host.call_result.output_data = std::data(call_output);

//     const auto code = delegatecall(0) + returndatasize() + ret_top();

//     host.call_result.status_code = EVMC_SUCCESS;
//     host.call_result.output_size = std::size(call_output);
//     execute(code);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 735);
//     EXPECT_OUTPUT_INT(std::size(call_output));

//     host.call_result.status_code = EVMC_FAILURE;
//     host.call_result.output_size = 1;
//     execute(code);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 735);
//     EXPECT_OUTPUT_INT(1);

//     host.call_result.status_code = EVMC_INTERNAL_ERROR;
//     host.call_result.output_size = 0;
//     execute(code);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 735);
//     EXPECT_OUTPUT_INT(0);
// }

// TEST_P(evm, returndatacopy)
// {
//     const auto call_output =
//         0x497f3c9f61479c1cfa53f0373d39d2bf4e5f73f71411da62f1d6b85c03a60735_bytes32;
//     host.call_result.output_data = std::data(call_output.bytes);
//     host.call_result.output_size = std::size(call_output.bytes);

//     const auto code = delegatecall(0) + returndatacopy(0, 0, 32) + ret(0, 32);
//     execute(code);
//     EXPECT_GAS_USED(EVMC_SUCCESS, 742);
//     EXPECT_EQ(bytes_view(result.output_data, result.output_size), call_output);
// }

// TEST_P(evm, returndatacopy_empty)
// {
//     execute(delegatecall(0) + returndatacopy(0, 0, 0) + ret(0, 32));
//     EXPECT_GAS_USED(EVMC_SUCCESS, 739);
//     EXPECT_OUTPUT_INT(0);
// }

// TEST_P(evm, returndatacopy_cost)
// {
//     const uint8_t call_output[1]{};
//     host.call_result.output_data = std::data(call_output);
//     host.call_result.output_size = std::size(call_output);

//     const auto code = staticcall(0) + returndatacopy(0, 0, 1);
//     execute(736, code);
//     EXPECT_EQ(result.status_code, EVMC_SUCCESS);
//     execute(735, code);
//     EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
// }

// TEST_P(evm, returndatacopy_outofrange)
// {
//     const uint8_t call_output[2]{};
//     host.call_result.output_data = std::data(call_output);
//     host.call_result.output_size = std::size(call_output);

//     execute(735, staticcall(0) + returndatacopy(0, 0, 3));
//     EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

//     execute(735, staticcall(0) + returndatacopy(0, 1, 2));
//     EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

//     execute(735, staticcall(0) + returndatacopy(0, 2, 1));
//     EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

//     execute(735, staticcall(0) + returndatacopy(0, 3, 0));
//     EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

//     execute(735, staticcall(0) + returndatacopy(0, 1, 0));
//     EXPECT_EQ(result.status_code, EVMC_SUCCESS);

//     execute(735, staticcall(0) + returndatacopy(0, 2, 0));
//     EXPECT_EQ(result.status_code, EVMC_SUCCESS);
// }

// TEST_P(evm, returndatacopy_outofrange_highbits)
// {
//     const uint8_t call_output[2]{};
//     host.call_result.output_data = std::data(call_output);
//     host.call_result.output_size = std::size(call_output);

//     // Covers an incorrect cast of RETURNDATALOAD arg to `size_t` ignoring the high bits.
//     const auto highbits =
//         0x1000000000000000000000000000000000000000000000000000000000000000_bytes32;
//     execute(735, staticcall(0) + returndatacopy(0, highbits, 0));
//     EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);
// }

TEST_P(evm, returndataload)
{
    // Not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    const auto call_output =
        0x497f3c9f61479c1cfa53f0373d39d2bf4e5f73f71411da62f1d6b85c03a60735_bytes32;
    host.call_result.output_data = std::data(call_output.bytes);
    host.call_result.output_size = std::size(call_output.bytes);
    const auto gas = 123123;
    host.call_result.gas_left = (gas - 3 - 3 - 3 - 100) * 63 / 64;

    const auto code = eof_bytecode(staticcall2(0) + returndataload(0) + ret_top(), 3);

    execute(gas, code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 131);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), call_output);
}

TEST_P(evm, returndataload_cost)
{
    // Not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    const uint8_t call_output[32]{};
    host.call_result.output_data = std::data(call_output);
    host.call_result.output_size = std::size(call_output);
    const auto gas = 123123;
    host.call_result.gas_left = (gas - 3 - 3 - 3 - 100) * 63 / 64;

    const auto code = eof_bytecode(staticcall2(0) + returndataload(0) + OP_STOP, 3);
    execute(109, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    execute(108, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_P(evm, returndataload_outofrange)
{
    // Not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    {
        const uint8_t call_output[31]{};
        host.call_result.output_data = std::data(call_output);
        host.call_result.output_size = std::size(call_output);

        execute(eof_bytecode(staticcall2(0) + returndataload(0) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);
    }
    {
        const uint8_t call_output[32]{};
        host.call_result.output_data = std::data(call_output);
        host.call_result.output_size = std::size(call_output);

        execute(eof_bytecode(staticcall2(0) + returndataload(1) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(31) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(32) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(max_uint256) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(0) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    }
    {
        const uint8_t call_output[34]{};
        host.call_result.output_data = std::data(call_output);
        host.call_result.output_size = std::size(call_output);

        execute(eof_bytecode(staticcall2(0) + returndataload(3) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(max_uint256) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(1) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(2) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    }
    {
        const uint8_t call_output[64]{};
        host.call_result.output_data = std::data(call_output);
        host.call_result.output_size = std::size(call_output);

        execute(eof_bytecode(staticcall2(0) + returndataload(33) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(max_uint256) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);


        execute(eof_bytecode(staticcall2(0) + returndataload(1) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(31) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        execute(eof_bytecode(staticcall2(0) + returndataload(32) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        execute(eof_bytecode(staticcall2(0) + returndataload(0) + OP_STOP, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    }
}

TEST_P(evm, returndataload_empty)
{
    // Not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    execute(eof_bytecode(staticcall2(0) + returndataload(0) + OP_STOP, 3));
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

    execute(eof_bytecode(staticcall2(0) + returndataload(1) + OP_STOP, 3));
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);

    execute(eof_bytecode(staticcall2(0) + returndataload(max_uint256) + OP_STOP, 3));
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);
}

TEST_P(evm, returndataload_outofrange_highbits)
{
    // Not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    const uint8_t call_output[34]{};
    host.call_result.output_data = std::data(call_output);
    host.call_result.output_size = std::size(call_output);

    // Covers an incorrect cast of RETURNDATALOAD arg to `size_t` ignoring the high bits.
    const auto highbits =
        0x1000000000000000000000000000000000000000000000000000000000000000_bytes32;
    execute(eof_bytecode(staticcall2(0) + returndataload(highbits) + OP_STOP, 3));
    EXPECT_EQ(result.status_code, EVMC_INVALID_MEMORY_ACCESS);
}

// TEST_P(evm, call_gas_refund_propagation)
// {
//     rev = EVMC_LONDON;
//     host.accounts[msg.recipient].set_balance(1);
//     host.call_result.status_code = EVMC_SUCCESS;
//     host.call_result.gas_refund = 1;

//     const auto code_prolog = 7 * push(1);
//     for (const auto op :
//         {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL, OP_CREATE, OP_CREATE2})
//     {
//         execute(code_prolog + op);
//         EXPECT_STATUS(EVMC_SUCCESS);
//         EXPECT_EQ(result.gas_refund, 1);
//     }
// }

// TEST_P(evm, call_gas_refund_aggregation_different_calls)
// {
//     rev = EVMC_LONDON;
//     host.accounts[msg.recipient].set_balance(1);
//     host.call_result.status_code = EVMC_SUCCESS;
//     host.call_result.gas_refund = 1;

//     const auto a = 0xaa_address;
//     const auto code =
//         call(a) + callcode(a) + delegatecall(a) + staticcall(a) + create() + create2();
//     execute(code);
//     EXPECT_STATUS(EVMC_SUCCESS);
//     EXPECT_EQ(result.gas_refund, 6);
// }

// TEST_P(evm, call_gas_refund_aggregation_same_calls)
// {
//     rev = EVMC_LONDON;
//     host.accounts[msg.recipient].set_balance(2);
//     host.call_result.status_code = EVMC_SUCCESS;
//     host.call_result.gas_refund = 1;

//     const auto code_prolog = 14 * push(1);
//     for (const auto op :
//         {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL, OP_CREATE, OP_CREATE2})
//     {
//         execute(code_prolog + 2 * op);
//         EXPECT_STATUS(EVMC_SUCCESS);
//         EXPECT_EQ(result.gas_refund, 2);
//     }
// }
