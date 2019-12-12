// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

/// This file contains non-mainstream EVM unit tests not matching any concrete category:
/// - regression tests,
/// - tests from fuzzers,
/// - evmone's internal tests.

#include "evm_fixture.hpp"

#include <evmone/limits.hpp>

using evm_other = evm;

TEST_F(evm_other, evmone_loaded_program_relocation)
{
    // The bytecode of size 2 will create evmone's loaded program of size 4 and will cause
    // the relocation of the C++ vector containing the program instructions.
    execute(bytecode{} + OP_STOP + OP_ORIGIN);
    EXPECT_GAS_USED(EVMC_SUCCESS, 0);
}

TEST_F(evm_other, evmone_block_stack_req_overflow)
{
    // This tests constructs a code with single basic block which stack requirement is > int16 max.
    // Such basic block can cause int16_t overflow during analysis.
    // The CALL instruction is going to be used because it has -6 stack change.

    const auto code = push(1) + 10 * OP_DUP1 + 5463 * OP_CALL;
    execute(code);
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);

    execute(code + ret_top());  // A variant with terminator.
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);
}

TEST_F(evm_other, evmone_block_max_stack_growth_overflow)
{
    // This tests constructs a code with single basic block which stack max growth is > int16 max.
    // Such basic block can cause int16_t overflow during analysis.

    constexpr auto test_max_code_size = 1024 * 1024u + 1;

    bytes code_buffer(test_max_code_size, uint8_t{OP_MSIZE});

    for (auto max_stack_growth : {32767u, 32768u, 65535u, 65536u, test_max_code_size - 1})
    {
        execute({code_buffer.data(), max_stack_growth});
        EXPECT_STATUS(EVMC_STACK_OVERFLOW);

        code_buffer[max_stack_growth] = OP_JUMPDEST;
        execute({code_buffer.data(), max_stack_growth + 1});
        EXPECT_STATUS(EVMC_STACK_OVERFLOW);

        code_buffer[max_stack_growth] = OP_STOP;
        execute({code_buffer.data(), max_stack_growth + 1});
        EXPECT_STATUS(EVMC_STACK_OVERFLOW);

        code_buffer[max_stack_growth] = OP_MSIZE;  // Restore original opcode.
    }
}

TEST_F(evm_other, evmone_block_gas_cost_overflow_create)
{
    // The goal is to build bytecode with as many CREATE instructions (the most expensive one)
    // as possible but with having balanced stack.
    // The runtime values of arguments are not important.

    constexpr auto gas_max = std::numeric_limits<uint32_t>::max();
    constexpr auto n = gas_max / 32006 + 1;

    auto code = bytecode{OP_MSIZE};
    code.reserve(3 * n);
    for (uint32_t i = 0; i < n; ++i)
    {
        code.push_back(OP_DUP1);
        code.push_back(OP_DUP1);
        code.push_back(OP_CREATE);
    }
    EXPECT_EQ(code.size(), 402'580);

    execute(0, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_TRUE(host.recorded_calls.empty());
    host.recorded_calls.clear();

    execute(gas_max - 1, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_TRUE(host.recorded_calls.empty());
}

TEST_F(evm_other, evmone_block_gas_cost_overflow_balance)
{
    // Here we build single-block bytecode with as many BALANCE instructions as possible.

    rev = EVMC_ISTANBUL;  // Here BALANCE costs 700.

    constexpr auto gas_max = std::numeric_limits<uint32_t>::max();
    constexpr auto n = gas_max / 700 + 2;
    auto code = bytecode{bytes(n, OP_BALANCE)};
    code[0] = OP_ADDRESS;
    EXPECT_EQ(code.size(), 6'135'669);

    execute(0, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_TRUE(host.recorded_account_accesses.empty());
    host.recorded_account_accesses.clear();

    execute(gas_max - 1, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
    EXPECT_TRUE(host.recorded_account_accesses.empty());
}

TEST_F(evm_other, loop_full_of_jumpdests)
{
    // The code is a simple loop with a counter taken from the input or a constant (325) if the
    // input is zero. The loop body contains of only JUMPDESTs, as much as the code size limit
    // allows.

    // The `mul(325, iszero(dup1(calldataload(0)))) + OP_OR` is equivalent of
    // `((x == 0) * 325) | x`
    // what is
    // `x == 0 ? 325 : x`.

    // The `not_(0)` is -1 so we can do `loop_counter + (-1)` to decrease the loop counter.

    const auto code = push(15) + not_(0) + mul(325, iszero(dup1(calldataload(0)))) + OP_OR +
                      (max_code_size - 20) * OP_JUMPDEST + OP_DUP2 + OP_ADD + OP_DUP1 + OP_DUP4 +
                      OP_JUMPI;

    EXPECT_EQ(code.size(), max_code_size);

    execute(code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 7987882);
}

TEST_F(evm_other, jumpdest_with_high_offset)
{
    for (auto offset : {3u, 16383u, 16384u, 32767u, 32768u, 65535u, 65536u})
    {
        auto code = push(offset) + OP_JUMP;
        code.resize(offset, OP_INVALID);
        code.push_back(OP_JUMPDEST);
        execute(code);
        EXPECT_EQ(result.status_code, EVMC_SUCCESS) << "JUMPDEST at " << offset;
    }
}

TEST_F(evm_other, abiv2_revert)
{
    rev = EVMC_ISTANBUL;
    auto code =
        "60806040523480156100115760006000fd5b506004361061003b5760003560e01c8063f8a8fd6d146100415780"
        "63fe26e4c81461005f5761003b565b60006000fd5b61004961007d565b604051610056919061052c565b604051"
        "80910390f35b610067610097565b6040516100749190610509565b60405180910390f35b600061008d6101bd63"
        "ffffffff16565b9050610094565b90565b61009f6102c5565b6000600060005060000160006101000a81548160"
        "ff0219169083151502179055506000600060005060010160005060008154811015156100db57fe5b9060005260"
        "2060002090602091828204019190065b6101000a81548160ff0219169083151502179055506000600050604051"
        "8060400160405290816000820160009054906101000a900460ff16151515158152602001600182016000508054"
        "806020026020016040519081016040528092919081815260200182805480156101a75760200282019190600052"
        "6020600020906000905b82829054906101000a900460ff16151581526020019060010190602082600001049283"
        "0192600103820291508084116101715790505b50505050508152602001505090506101ba565b90565b60006101"
        "c76102c5565b3073ffffffffffffffffffffffffffffffffffffffff1663fe26e4c86040518163ffffffff1660"
        "e01b8152600401600060405180830381600087803b1580156102105760006000fd5b505af1158015610225573d"
        "600060003e3d6000fd5b505050506040513d6000823e3d601f19601f8201168201806040525061024e91908101"
        "906103ee565b9050600015158160000151151514151561026c5760019150506102c2565b600181602001515114"
        "15156102855760029150506102c2565b600015158160200151600081518110151561029c57fe5b602002602001"
        "015115151415156102b75760039150506102c2565b60009150506102c256505b90565b60405180604001604052"
        "8060001515815260200160608152602001509056610611565b600082601f83011215156102fc5760006000fd5b"
        "815161030f61030a82610577565b610548565b9150818183526020840193506020810190508385602084028201"
        "11156103355760006000fd5b60005b83811015610366578161034b8882610371565b8452602084019350602083"
        "019250505b600181019050610338565b505050505b92915050565b600081519050610380816105f6565b5b9291"
        "5050565b60006040828403121561039a5760006000fd5b6103a46040610548565b905060006103b48482850161"
        "0371565b600083015250602082015167ffffffffffffffff8111156103d55760006000fd5b6103e18482850161"
        "02e8565b6020830152505b92915050565b6000602082840312156104015760006000fd5b600082015167ffffff"
        "ffffffffff81111561041c5760006000fd5b61042884828501610387565b9150505b92915050565b600061043e"
        "83836104ab565b6020830190505b92915050565b6000610456826105b2565b61046081856105cc565b93506104"
        "6b836105a1565b8060005b8381101561049d5781516104838882610432565b975061048e836105be565b925050"
        "5b60018101905061046f565b508593505050505b92915050565b6104b4816105de565b82525b5050565b600060"
        "40830160008301516104d360008601826104ab565b50602083015184820360208601526104eb828261044b565b"
        "915050809150505b92915050565b610502816105eb565b82525b5050565b600060208201905081810360008301"
        "5261052381846104bb565b90505b92915050565b600060208201905061054160008301846104f9565b5b929150"
        "50565b6000604051905081810181811067ffffffffffffffff8211171561056c5760006000fd5b80604052505b"
        "919050565b600067ffffffffffffffff82111561058f5760006000fd5b6020820290506020810190505b919050"
        "565b60008190506020820190505b919050565b6000815190505b919050565b60006020820190505b919050565b"
        "60008282526020820190505b92915050565b600081151590505b919050565b60008190505b919050565b6105ff"
        "816105de565b8114151561060d5760006000fd5b5b50565bfea2646970667358221220712c5b5d6d1770e8a361"
        "1ace8798753a184c422d91e9fecfa124db917da9e5cb64736f6c63782c302e362e302d646576656c6f702e3230"
        "31392e31322e31312b636f6d6d69742e35333839653033662e6d6f64005d";
    execute(code, "f8a8fd6d");
    EXPECT_STATUS(EVMC_SUCCESS);
}