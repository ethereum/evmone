// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/instructions.h>
#include <array>

namespace evmone::instr
{
/// The EVM instruction traits.
struct Traits
{
    /// The number of stack items the instruction accesses during execution.
    int8_t stack_height_required = 0;

    /// The stack height change caused by the instruction execution. Can be negative.
    int8_t stack_height_change = 0;
};

/// The global, EVM revision independent, table of traits of all known EVM instructions.
constexpr std::array<Traits, 256> traits = []() noexcept {
    std::array<Traits, 256> table{};

    table[OP_STOP] = {0, 0};
    table[OP_ADD] = {2, -1};
    table[OP_MUL] = {2, -1};
    table[OP_SUB] = {2, -1};
    table[OP_DIV] = {2, -1};
    table[OP_SDIV] = {2, -1};
    table[OP_MOD] = {2, -1};
    table[OP_SMOD] = {2, -1};
    table[OP_ADDMOD] = {3, -2};
    table[OP_MULMOD] = {3, -2};
    table[OP_EXP] = {2, -1};
    table[OP_SIGNEXTEND] = {2, -1};

    table[OP_LT] = {2, -1};
    table[OP_GT] = {2, -1};
    table[OP_SLT] = {2, -1};
    table[OP_SGT] = {2, -1};
    table[OP_EQ] = {2, -1};
    table[OP_ISZERO] = {1, 0};
    table[OP_AND] = {2, -1};
    table[OP_OR] = {2, -1};
    table[OP_XOR] = {2, -1};
    table[OP_NOT] = {1, 0};
    table[OP_BYTE] = {2, -1};
    table[OP_SHL] = {2, -1};
    table[OP_SHR] = {2, -1};
    table[OP_SAR] = {2, -1};

    table[OP_SHA3] = {2, -1};

    table[OP_ADDRESS] = {0, 1};
    table[OP_BALANCE] = {1, 0};
    table[OP_ORIGIN] = {0, 1};
    table[OP_CALLER] = {0, 1};
    table[OP_CALLVALUE] = {0, 1};
    table[OP_CALLDATALOAD] = {1, 0};
    table[OP_CALLDATASIZE] = {0, 1};
    table[OP_CALLDATACOPY] = {3, -3};
    table[OP_CODESIZE] = {0, 1};
    table[OP_CODECOPY] = {3, -3};
    table[OP_GASPRICE] = {0, 1};
    table[OP_EXTCODESIZE] = {1, 0};
    table[OP_EXTCODECOPY] = {4, -4};
    table[OP_RETURNDATASIZE] = {0, 1};
    table[OP_RETURNDATACOPY] = {3, -3};
    table[OP_EXTCODEHASH] = {1, 0};

    table[OP_BLOCKHASH] = {1, 0};
    table[OP_COINBASE] = {0, 1};
    table[OP_TIMESTAMP] = {0, 1};
    table[OP_NUMBER] = {0, 1};
    table[OP_DIFFICULTY] = {0, 1};
    table[OP_GASLIMIT] = {0, 1};
    table[OP_CHAINID] = {0, 1};
    table[OP_SELFBALANCE] = {0, 1};

    table[OP_POP] = {1, -1};
    table[OP_MLOAD] = {1, 0};
    table[OP_MSTORE] = {2, -2};
    table[OP_MSTORE8] = {2, -2};
    table[OP_SLOAD] = {1, 0};
    table[OP_SSTORE] = {2, -2};
    table[OP_JUMP] = {1, -1};
    table[OP_JUMPI] = {2, -2};
    table[OP_PC] = {0, 1};
    table[OP_MSIZE] = {0, 1};
    table[OP_GAS] = {0, 1};
    table[OP_JUMPDEST] = {0, 0};

    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH32; ++op)
        table[op] = {0, 1};

    for (auto op = size_t{OP_DUP1}; op <= OP_DUP16; ++op)
        table[op] = {static_cast<int8_t>(op - OP_DUP1 + 1), 1};

    for (auto op = size_t{OP_SWAP1}; op <= OP_SWAP16; ++op)
        table[op] = {static_cast<int8_t>(op - OP_SWAP1 + 2), 0};

    for (auto op = size_t{OP_LOG0}; op <= OP_LOG4; ++op)
    {
        const auto num_operands = static_cast<int>(op - OP_LOG0 + 2);
        table[op] = {static_cast<int8_t>(num_operands), static_cast<int8_t>(-num_operands)};
    }

    table[OP_CREATE] = {3, -2};
    table[OP_CALL] = {7, -6};
    table[OP_CALLCODE] = {7, -6};
    table[OP_RETURN] = {2, -2};
    table[OP_DELEGATECALL] = {6, -5};
    table[OP_CREATE2] = {4, -3};
    table[OP_STATICCALL] = {6, -5};
    table[OP_REVERT] = {2, -2};
    table[OP_INVALID] = {0, 0};
    table[OP_SELFDESTRUCT] = {1, -1};

    return table;
}();

/// The special gas cost value marking an EVM instruction as "undefined".
constexpr int16_t undefined = -1;

/// The EVM revision specific table of EVM instructions gas costs. For instructions undefined
/// in given EVM revision, the value is instr::undefined.
template <evmc_revision>
constexpr auto gas_costs = nullptr;


template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_FRONTIER> = []() noexcept {
    std::array<int16_t, 256> table{};
    for (auto& t : table)
        t = undefined;

    table[OP_STOP] = 0;
    table[OP_ADD] = 3;
    table[OP_MUL] = 5;
    table[OP_SUB] = 3;
    table[OP_DIV] = 5;
    table[OP_SDIV] = 5;
    table[OP_MOD] = 5;
    table[OP_SMOD] = 5;
    table[OP_ADDMOD] = 8;
    table[OP_MULMOD] = 8;
    table[OP_EXP] = 10;
    table[OP_SIGNEXTEND] = 5;
    table[OP_LT] = 3;
    table[OP_GT] = 3;
    table[OP_SLT] = 3;
    table[OP_SGT] = 3;
    table[OP_EQ] = 3;
    table[OP_ISZERO] = 3;
    table[OP_AND] = 3;
    table[OP_OR] = 3;
    table[OP_XOR] = 3;
    table[OP_NOT] = 3;
    table[OP_BYTE] = 3;
    table[OP_SHA3] = 30;
    table[OP_ADDRESS] = 2;
    table[OP_BALANCE] = 20;
    table[OP_ORIGIN] = 2;
    table[OP_CALLER] = 2;
    table[OP_CALLVALUE] = 2;
    table[OP_CALLDATALOAD] = 3;
    table[OP_CALLDATASIZE] = 2;
    table[OP_CALLDATACOPY] = 3;
    table[OP_CODESIZE] = 2;
    table[OP_CODECOPY] = 3;
    table[OP_GASPRICE] = 2;
    table[OP_EXTCODESIZE] = 20;
    table[OP_EXTCODECOPY] = 20;
    table[OP_BLOCKHASH] = 20;
    table[OP_COINBASE] = 2;
    table[OP_TIMESTAMP] = 2;
    table[OP_NUMBER] = 2;
    table[OP_DIFFICULTY] = 2;
    table[OP_GASLIMIT] = 2;
    table[OP_POP] = 2;
    table[OP_MLOAD] = 3;
    table[OP_MSTORE] = 3;
    table[OP_MSTORE8] = 3;
    table[OP_SLOAD] = 50;
    table[OP_SSTORE] = 0;
    table[OP_JUMP] = 8;
    table[OP_JUMPI] = 10;
    table[OP_PC] = 2;
    table[OP_MSIZE] = 2;

    table[OP_GAS] = 2;
    table[OP_JUMPDEST] = 1;

    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH32; ++op)
        table[op] = 3;

    for (auto op = size_t{OP_DUP1}; op <= OP_DUP16; ++op)
        table[op] = 3;

    for (auto op = size_t{OP_SWAP1}; op <= OP_SWAP16; ++op)
        table[op] = 3;

    for (auto op = size_t{OP_LOG0}; op <= OP_LOG4; ++op)
        table[op] = static_cast<int16_t>((op - OP_LOG0 + 1) * 375);

    table[OP_CREATE] = 32000;
    table[OP_CALL] = 40;
    table[OP_CALLCODE] = 40;
    table[OP_RETURN] = 0;
    table[OP_INVALID] = 0;
    table[OP_SELFDESTRUCT] = 0;
    return table;
}();

template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_HOMESTEAD> = []() noexcept {
    auto table = gas_costs<EVMC_FRONTIER>;
    table[OP_DELEGATECALL] = 40;
    return table;
}();

template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_TANGERINE_WHISTLE> = []() noexcept {
    auto table = gas_costs<EVMC_HOMESTEAD>;
    table[OP_BALANCE] = 400;
    table[OP_EXTCODESIZE] = 700;
    table[OP_EXTCODECOPY] = 700;
    table[OP_SLOAD] = 200;
    table[OP_CALL] = 700;
    table[OP_CALLCODE] = 700;
    table[OP_DELEGATECALL] = 700;
    table[OP_SELFDESTRUCT] = 5000;
    return table;
}();

template <>
constexpr auto gas_costs<EVMC_SPURIOUS_DRAGON> = gas_costs<EVMC_TANGERINE_WHISTLE>;

template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_BYZANTIUM> = []() noexcept {
    auto table = gas_costs<EVMC_SPURIOUS_DRAGON>;
    table[OP_RETURNDATASIZE] = 2;
    table[OP_RETURNDATACOPY] = 3;
    table[OP_STATICCALL] = 700;
    table[OP_REVERT] = 0;
    return table;
}();

template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_CONSTANTINOPLE> = []() noexcept {
    auto table = gas_costs<EVMC_BYZANTIUM>;
    table[OP_SHL] = 3;
    table[OP_SHR] = 3;
    table[OP_SAR] = 3;
    table[OP_EXTCODEHASH] = 400;
    table[OP_CREATE2] = 32000;
    return table;
}();

template <>
constexpr auto gas_costs<EVMC_PETERSBURG> = gas_costs<EVMC_CONSTANTINOPLE>;

template <>
constexpr std::array<int16_t, 256> gas_costs<EVMC_ISTANBUL> = []() noexcept {
    auto table = gas_costs<EVMC_CONSTANTINOPLE>;
    table[OP_BALANCE] = 700;
    table[OP_CHAINID] = 2;
    table[OP_EXTCODEHASH] = 700;
    table[OP_SELFBALANCE] = 5;
    table[OP_SLOAD] = 800;
    return table;
}();

template <>
constexpr auto gas_costs<EVMC_BERLIN> = gas_costs<EVMC_ISTANBUL>;
}  // namespace evmone::instr
