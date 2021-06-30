// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/instructions.h>
#include <array>

namespace evmone::instr
{
/// The special gas cost value marking an EVM instruction as "undefined".
constexpr int16_t undefined = -1;

/// EIP-2929 constants (https://eips.ethereum.org/EIPS/eip-2929).
/// @{
inline constexpr auto cold_sload_cost = 2100;
inline constexpr auto cold_account_access_cost = 2600;
inline constexpr auto warm_storage_read_cost = 100;

/// Additional cold account access cost.
///
/// The warm access cost is unconditionally applied for every account access instruction.
/// If the access turns out to be cold, this cost must be applied additionally.
inline constexpr auto additional_cold_account_access_cost =
    cold_account_access_cost - warm_storage_read_cost;
/// @}


/// The table of instruction gas costs per EVM revision.
using GasCostTable = std::array<std::array<int16_t, 256>, EVMC_MAX_REVISION + 1>;

/// The EVM revision specific table of EVM instructions gas costs. For instructions undefined
/// in given EVM revision, the value is instr::undefined.
constexpr inline GasCostTable gas_costs = []() noexcept {
    GasCostTable table{};

    for (auto& t : table[EVMC_FRONTIER])
        t = undefined;
    table[EVMC_FRONTIER][OP_STOP] = 0;
    table[EVMC_FRONTIER][OP_ADD] = 3;
    table[EVMC_FRONTIER][OP_MUL] = 5;
    table[EVMC_FRONTIER][OP_SUB] = 3;
    table[EVMC_FRONTIER][OP_DIV] = 5;
    table[EVMC_FRONTIER][OP_SDIV] = 5;
    table[EVMC_FRONTIER][OP_MOD] = 5;
    table[EVMC_FRONTIER][OP_SMOD] = 5;
    table[EVMC_FRONTIER][OP_ADDMOD] = 8;
    table[EVMC_FRONTIER][OP_MULMOD] = 8;
    table[EVMC_FRONTIER][OP_EXP] = 10;
    table[EVMC_FRONTIER][OP_SIGNEXTEND] = 5;
    table[EVMC_FRONTIER][OP_LT] = 3;
    table[EVMC_FRONTIER][OP_GT] = 3;
    table[EVMC_FRONTIER][OP_SLT] = 3;
    table[EVMC_FRONTIER][OP_SGT] = 3;
    table[EVMC_FRONTIER][OP_EQ] = 3;
    table[EVMC_FRONTIER][OP_ISZERO] = 3;
    table[EVMC_FRONTIER][OP_AND] = 3;
    table[EVMC_FRONTIER][OP_OR] = 3;
    table[EVMC_FRONTIER][OP_XOR] = 3;
    table[EVMC_FRONTIER][OP_NOT] = 3;
    table[EVMC_FRONTIER][OP_BYTE] = 3;
    table[EVMC_FRONTIER][OP_KECCAK256] = 30;
    table[EVMC_FRONTIER][OP_ADDRESS] = 2;
    table[EVMC_FRONTIER][OP_BALANCE] = 20;
    table[EVMC_FRONTIER][OP_ORIGIN] = 2;
    table[EVMC_FRONTIER][OP_CALLER] = 2;
    table[EVMC_FRONTIER][OP_CALLVALUE] = 2;
    table[EVMC_FRONTIER][OP_CALLDATALOAD] = 3;
    table[EVMC_FRONTIER][OP_CALLDATASIZE] = 2;
    table[EVMC_FRONTIER][OP_CALLDATACOPY] = 3;
    table[EVMC_FRONTIER][OP_CODESIZE] = 2;
    table[EVMC_FRONTIER][OP_CODECOPY] = 3;
    table[EVMC_FRONTIER][OP_GASPRICE] = 2;
    table[EVMC_FRONTIER][OP_EXTCODESIZE] = 20;
    table[EVMC_FRONTIER][OP_EXTCODECOPY] = 20;
    table[EVMC_FRONTIER][OP_BLOCKHASH] = 20;
    table[EVMC_FRONTIER][OP_COINBASE] = 2;
    table[EVMC_FRONTIER][OP_TIMESTAMP] = 2;
    table[EVMC_FRONTIER][OP_NUMBER] = 2;
    table[EVMC_FRONTIER][OP_DIFFICULTY] = 2;
    table[EVMC_FRONTIER][OP_GASLIMIT] = 2;
    table[EVMC_FRONTIER][OP_POP] = 2;
    table[EVMC_FRONTIER][OP_MLOAD] = 3;
    table[EVMC_FRONTIER][OP_MSTORE] = 3;
    table[EVMC_FRONTIER][OP_MSTORE8] = 3;
    table[EVMC_FRONTIER][OP_SLOAD] = 50;
    table[EVMC_FRONTIER][OP_SSTORE] = 0;
    table[EVMC_FRONTIER][OP_JUMP] = 8;
    table[EVMC_FRONTIER][OP_JUMPI] = 10;
    table[EVMC_FRONTIER][OP_PC] = 2;
    table[EVMC_FRONTIER][OP_MSIZE] = 2;
    table[EVMC_FRONTIER][OP_GAS] = 2;
    table[EVMC_FRONTIER][OP_JUMPDEST] = 1;
    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH32; ++op)
        table[EVMC_FRONTIER][op] = 3;
    for (auto op = size_t{OP_DUP1}; op <= OP_DUP16; ++op)
        table[EVMC_FRONTIER][op] = 3;
    for (auto op = size_t{OP_SWAP1}; op <= OP_SWAP16; ++op)
        table[EVMC_FRONTIER][op] = 3;
    for (auto op = size_t{OP_LOG0}; op <= OP_LOG4; ++op)
        table[EVMC_FRONTIER][op] = static_cast<int16_t>((op - OP_LOG0 + 1) * 375);
    table[EVMC_FRONTIER][OP_CREATE] = 32000;
    table[EVMC_FRONTIER][OP_CALL] = 40;
    table[EVMC_FRONTIER][OP_CALLCODE] = 40;
    table[EVMC_FRONTIER][OP_RETURN] = 0;
    table[EVMC_FRONTIER][OP_INVALID] = 0;
    table[EVMC_FRONTIER][OP_SELFDESTRUCT] = 0;

    table[EVMC_HOMESTEAD] = table[EVMC_FRONTIER];
    table[EVMC_HOMESTEAD][OP_DELEGATECALL] = 40;

    table[EVMC_TANGERINE_WHISTLE] = table[EVMC_HOMESTEAD];
    table[EVMC_TANGERINE_WHISTLE][OP_BALANCE] = 400;
    table[EVMC_TANGERINE_WHISTLE][OP_EXTCODESIZE] = 700;
    table[EVMC_TANGERINE_WHISTLE][OP_EXTCODECOPY] = 700;
    table[EVMC_TANGERINE_WHISTLE][OP_SLOAD] = 200;
    table[EVMC_TANGERINE_WHISTLE][OP_CALL] = 700;
    table[EVMC_TANGERINE_WHISTLE][OP_CALLCODE] = 700;
    table[EVMC_TANGERINE_WHISTLE][OP_DELEGATECALL] = 700;
    table[EVMC_TANGERINE_WHISTLE][OP_SELFDESTRUCT] = 5000;

    table[EVMC_SPURIOUS_DRAGON] = table[EVMC_TANGERINE_WHISTLE];

    table[EVMC_BYZANTIUM] = table[EVMC_SPURIOUS_DRAGON];
    table[EVMC_BYZANTIUM][OP_RETURNDATASIZE] = 2;
    table[EVMC_BYZANTIUM][OP_RETURNDATACOPY] = 3;
    table[EVMC_BYZANTIUM][OP_STATICCALL] = 700;
    table[EVMC_BYZANTIUM][OP_REVERT] = 0;

    table[EVMC_CONSTANTINOPLE] = table[EVMC_BYZANTIUM];
    table[EVMC_CONSTANTINOPLE][OP_SHL] = 3;
    table[EVMC_CONSTANTINOPLE][OP_SHR] = 3;
    table[EVMC_CONSTANTINOPLE][OP_SAR] = 3;
    table[EVMC_CONSTANTINOPLE][OP_EXTCODEHASH] = 400;
    table[EVMC_CONSTANTINOPLE][OP_CREATE2] = 32000;

    table[EVMC_PETERSBURG] = table[EVMC_CONSTANTINOPLE];

    table[EVMC_ISTANBUL] = table[EVMC_PETERSBURG];
    table[EVMC_ISTANBUL][OP_BALANCE] = 700;
    table[EVMC_ISTANBUL][OP_CHAINID] = 2;
    table[EVMC_ISTANBUL][OP_EXTCODEHASH] = 700;
    table[EVMC_ISTANBUL][OP_SELFBALANCE] = 5;
    table[EVMC_ISTANBUL][OP_SLOAD] = 800;

    table[EVMC_BERLIN] = table[EVMC_ISTANBUL];
    table[EVMC_BERLIN][OP_EXTCODESIZE] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_EXTCODECOPY] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_EXTCODEHASH] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_BALANCE] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_CALL] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_CALLCODE] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_DELEGATECALL] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_STATICCALL] = warm_storage_read_cost;
    table[EVMC_BERLIN][OP_SLOAD] = warm_storage_read_cost;

    table[EVMC_LONDON] = table[EVMC_BERLIN];
    table[EVMC_LONDON][OP_BASEFEE] = 2;

    table[EVMC_SHANGHAI] = table[EVMC_LONDON];

    return table;
}();

static_assert(gas_costs[EVMC_MAX_REVISION][OP_ADD] > 0, "gas costs missing for a revision");


/// The EVM instruction traits.
struct Traits
{
    /// The instruction name;
    const char* name = nullptr;

    /// The number of stack items the instruction accesses during execution.
    int8_t stack_height_required = 0;

    /// The stack height change caused by the instruction execution. Can be negative.
    int8_t stack_height_change = 0;
};

/// The global, EVM revision independent, table of traits of all known EVM instructions.
constexpr inline std::array<Traits, 256> traits = []() noexcept {
    std::array<Traits, 256> table{};

    table[OP_STOP] = {"STOP", 0, 0};
    table[OP_ADD] = {"ADD", 2, -1};
    table[OP_MUL] = {"MUL", 2, -1};
    table[OP_SUB] = {"SUB", 2, -1};
    table[OP_DIV] = {"DIV", 2, -1};
    table[OP_SDIV] = {"SDIV", 2, -1};
    table[OP_MOD] = {"MOD", 2, -1};
    table[OP_SMOD] = {"SMOD", 2, -1};
    table[OP_ADDMOD] = {"ADDMOD", 3, -2};
    table[OP_MULMOD] = {"MULMOD", 3, -2};
    table[OP_EXP] = {"EXP", 2, -1};
    table[OP_SIGNEXTEND] = {"SIGNEXTEND", 2, -1};

    table[OP_LT] = {"LT", 2, -1};
    table[OP_GT] = {"GT", 2, -1};
    table[OP_SLT] = {"SLT", 2, -1};
    table[OP_SGT] = {"SGT", 2, -1};
    table[OP_EQ] = {"EQ", 2, -1};
    table[OP_ISZERO] = {"ISZERO", 1, 0};
    table[OP_AND] = {"AND", 2, -1};
    table[OP_OR] = {"OR", 2, -1};
    table[OP_XOR] = {"XOR", 2, -1};
    table[OP_NOT] = {"NOT", 1, 0};
    table[OP_BYTE] = {"BYTE", 2, -1};
    table[OP_SHL] = {"SHL", 2, -1};
    table[OP_SHR] = {"SHR", 2, -1};
    table[OP_SAR] = {"SAR", 2, -1};

    table[OP_KECCAK256] = {"KECCAK256", 2, -1};

    table[OP_ADDRESS] = {"ADDRESS", 0, 1};
    table[OP_BALANCE] = {"BALANCE", 1, 0};
    table[OP_ORIGIN] = {"ORIGIN", 0, 1};
    table[OP_CALLER] = {"CALLER", 0, 1};
    table[OP_CALLVALUE] = {"CALLVALUE", 0, 1};
    table[OP_CALLDATALOAD] = {"CALLDATALOAD", 1, 0};
    table[OP_CALLDATASIZE] = {"CALLDATASIZE", 0, 1};
    table[OP_CALLDATACOPY] = {"CALLDATACOPY", 3, -3};
    table[OP_CODESIZE] = {"CODESIZE", 0, 1};
    table[OP_CODECOPY] = {"CODECOPY", 3, -3};
    table[OP_GASPRICE] = {"GASPRICE", 0, 1};
    table[OP_EXTCODESIZE] = {"EXTCODESIZE", 1, 0};
    table[OP_EXTCODECOPY] = {"EXTCODECOPY", 4, -4};
    table[OP_RETURNDATASIZE] = {"RETURNDATASIZE", 0, 1};
    table[OP_RETURNDATACOPY] = {"RETURNDATACOPY", 3, -3};
    table[OP_EXTCODEHASH] = {"EXTCODEHASH", 1, 0};

    table[OP_BLOCKHASH] = {"BLOCKHASH", 1, 0};
    table[OP_COINBASE] = {"COINBASE", 0, 1};
    table[OP_TIMESTAMP] = {"TIMESTAMP", 0, 1};
    table[OP_NUMBER] = {"NUMBER", 0, 1};
    table[OP_DIFFICULTY] = {"DIFFICULTY", 0, 1};
    table[OP_GASLIMIT] = {"GASLIMIT", 0, 1};
    table[OP_CHAINID] = {"CHAINID", 0, 1};
    table[OP_SELFBALANCE] = {"SELFBALANCE", 0, 1};
    table[OP_BASEFEE] = {"BASEFEE", 0, 1};

    table[OP_POP] = {"POP", 1, -1};
    table[OP_MLOAD] = {"MLOAD", 1, 0};
    table[OP_MSTORE] = {"MSTORE", 2, -2};
    table[OP_MSTORE8] = {"MSTORE8", 2, -2};
    table[OP_SLOAD] = {"SLOAD", 1, 0};
    table[OP_SSTORE] = {"SSTORE", 2, -2};
    table[OP_JUMP] = {"JUMP", 1, -1};
    table[OP_JUMPI] = {"JUMPI", 2, -2};
    table[OP_PC] = {"PC", 0, 1};
    table[OP_MSIZE] = {"MSIZE", 0, 1};
    table[OP_GAS] = {"GAS", 0, 1};
    table[OP_JUMPDEST] = {"JUMPDEST", 0, 0};

    table[OP_PUSH1] = {"PUSH1", 0, 1};
    table[OP_PUSH2] = {"PUSH2", 0, 1};
    table[OP_PUSH3] = {"PUSH3", 0, 1};
    table[OP_PUSH4] = {"PUSH4", 0, 1};
    table[OP_PUSH5] = {"PUSH5", 0, 1};
    table[OP_PUSH6] = {"PUSH6", 0, 1};
    table[OP_PUSH7] = {"PUSH7", 0, 1};
    table[OP_PUSH8] = {"PUSH8", 0, 1};
    table[OP_PUSH9] = {"PUSH9", 0, 1};
    table[OP_PUSH10] = {"PUSH10", 0, 1};
    table[OP_PUSH11] = {"PUSH11", 0, 1};
    table[OP_PUSH12] = {"PUSH12", 0, 1};
    table[OP_PUSH13] = {"PUSH13", 0, 1};
    table[OP_PUSH14] = {"PUSH14", 0, 1};
    table[OP_PUSH15] = {"PUSH15", 0, 1};
    table[OP_PUSH16] = {"PUSH16", 0, 1};
    table[OP_PUSH17] = {"PUSH17", 0, 1};
    table[OP_PUSH18] = {"PUSH18", 0, 1};
    table[OP_PUSH19] = {"PUSH19", 0, 1};
    table[OP_PUSH20] = {"PUSH20", 0, 1};
    table[OP_PUSH21] = {"PUSH21", 0, 1};
    table[OP_PUSH22] = {"PUSH22", 0, 1};
    table[OP_PUSH23] = {"PUSH23", 0, 1};
    table[OP_PUSH24] = {"PUSH24", 0, 1};
    table[OP_PUSH25] = {"PUSH25", 0, 1};
    table[OP_PUSH26] = {"PUSH26", 0, 1};
    table[OP_PUSH27] = {"PUSH27", 0, 1};
    table[OP_PUSH28] = {"PUSH28", 0, 1};
    table[OP_PUSH29] = {"PUSH29", 0, 1};
    table[OP_PUSH30] = {"PUSH30", 0, 1};
    table[OP_PUSH31] = {"PUSH31", 0, 1};
    table[OP_PUSH32] = {"PUSH32", 0, 1};

    table[OP_DUP1] = {"DUP1", 1, 1};
    table[OP_DUP2] = {"DUP2", 2, 1};
    table[OP_DUP3] = {"DUP3", 3, 1};
    table[OP_DUP4] = {"DUP4", 4, 1};
    table[OP_DUP5] = {"DUP5", 5, 1};
    table[OP_DUP6] = {"DUP6", 6, 1};
    table[OP_DUP7] = {"DUP7", 7, 1};
    table[OP_DUP8] = {"DUP8", 8, 1};
    table[OP_DUP9] = {"DUP9", 9, 1};
    table[OP_DUP10] = {"DUP10", 10, 1};
    table[OP_DUP11] = {"DUP11", 11, 1};
    table[OP_DUP12] = {"DUP12", 12, 1};
    table[OP_DUP13] = {"DUP13", 13, 1};
    table[OP_DUP14] = {"DUP14", 14, 1};
    table[OP_DUP15] = {"DUP15", 15, 1};
    table[OP_DUP16] = {"DUP16", 16, 1};

    table[OP_SWAP1] = {"SWAP1", 2, 0};
    table[OP_SWAP2] = {"SWAP2", 3, 0};
    table[OP_SWAP3] = {"SWAP3", 4, 0};
    table[OP_SWAP4] = {"SWAP4", 5, 0};
    table[OP_SWAP5] = {"SWAP5", 6, 0};
    table[OP_SWAP6] = {"SWAP6", 7, 0};
    table[OP_SWAP7] = {"SWAP7", 8, 0};
    table[OP_SWAP8] = {"SWAP8", 9, 0};
    table[OP_SWAP9] = {"SWAP9", 10, 0};
    table[OP_SWAP10] = {"SWAP10", 11, 0};
    table[OP_SWAP11] = {"SWAP11", 12, 0};
    table[OP_SWAP12] = {"SWAP12", 13, 0};
    table[OP_SWAP13] = {"SWAP13", 14, 0};
    table[OP_SWAP14] = {"SWAP14", 15, 0};
    table[OP_SWAP15] = {"SWAP15", 16, 0};
    table[OP_SWAP16] = {"SWAP16", 17, 0};

    table[OP_LOG0] = {"LOG0", 2, -2};
    table[OP_LOG1] = {"LOG1", 3, -3};
    table[OP_LOG2] = {"LOG2", 4, -4};
    table[OP_LOG3] = {"LOG3", 5, -5};
    table[OP_LOG4] = {"LOG4", 6, -6};

    table[OP_CREATE] = {"CREATE", 3, -2};
    table[OP_CALL] = {"CALL", 7, -6};
    table[OP_CALLCODE] = {"CALLCODE", 7, -6};
    table[OP_RETURN] = {"RETURN", 2, -2};
    table[OP_DELEGATECALL] = {"DELEGATECALL", 6, -5};
    table[OP_CREATE2] = {"CREATE2", 4, -3};
    table[OP_STATICCALL] = {"STATICCALL", 6, -5};
    table[OP_REVERT] = {"REVERT", 2, -2};
    table[OP_INVALID] = {"INVALID", 0, 0};
    table[OP_SELFDESTRUCT] = {"SELFDESTRUCT", 1, -1};

    return table;
}();

}  // namespace evmone::instr
