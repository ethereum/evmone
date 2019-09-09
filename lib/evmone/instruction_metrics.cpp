// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include "instruction_metrics.hpp"
#include <array>

namespace evmone
{
namespace
{
using metrics_table = std::array<instruction_metrics, 256>;

constexpr metrics_table build_frontier_metrics() noexcept
{
    auto metrics = metrics_table{};
    metrics[OP_STOP] = {0, 0, 0, terminator};
    metrics[OP_ADD] = {3, 2, -1, regular};
    metrics[OP_MUL] = {5, 2, -1, regular};
    metrics[OP_SUB] = {3, 2, -1, regular};
    metrics[OP_DIV] = {5, 2, -1, regular};
    metrics[OP_SDIV] = {5, 2, -1, regular};
    metrics[OP_MOD] = {5, 2, -1, regular};
    metrics[OP_SMOD] = {5, 2, -1, regular};
    metrics[OP_ADDMOD] = {8, 3, -2, regular};
    metrics[OP_MULMOD] = {8, 3, -2, regular};
    metrics[OP_EXP] = {10, 2, -1, regular};
    metrics[OP_SIGNEXTEND] = {5, 2, -1, regular};
    metrics[OP_LT] = {3, 2, -1, regular};
    metrics[OP_GT] = {3, 2, -1, regular};
    metrics[OP_SLT] = {3, 2, -1, regular};
    metrics[OP_SGT] = {3, 2, -1, regular};
    metrics[OP_EQ] = {3, 2, -1, regular};
    metrics[OP_ISZERO] = {3, 1, 0, regular};
    metrics[OP_AND] = {3, 2, -1, regular};
    metrics[OP_OR] = {3, 2, -1, regular};
    metrics[OP_XOR] = {3, 2, -1, regular};
    metrics[OP_NOT] = {3, 1, 0, regular};
    metrics[OP_BYTE] = {3, 2, -1, regular};
    metrics[OP_SHA3] = {30, 2, -1, regular};
    metrics[OP_ADDRESS] = {2, 0, 1, regular};
    metrics[OP_BALANCE] = {20, 1, 0, regular};
    metrics[OP_ORIGIN] = {2, 0, 1, regular};
    metrics[OP_CALLER] = {2, 0, 1, regular};
    metrics[OP_CALLVALUE] = {2, 0, 1, regular};
    metrics[OP_CALLDATALOAD] = {3, 1, 0, regular};
    metrics[OP_CALLDATASIZE] = {2, 0, 1, regular};
    metrics[OP_CALLDATACOPY] = {3, 3, -3, regular};
    metrics[OP_CODESIZE] = {2, 0, 1, regular};
    metrics[OP_CODECOPY] = {3, 3, -3, regular};
    metrics[OP_GASPRICE] = {2, 0, 1, regular};
    metrics[OP_EXTCODESIZE] = {20, 1, 0, regular};
    metrics[OP_EXTCODECOPY] = {20, 4, -4, regular};
    metrics[OP_BLOCKHASH] = {20, 1, 0, regular};
    metrics[OP_COINBASE] = {2, 0, 1, regular};
    metrics[OP_TIMESTAMP] = {2, 0, 1, regular};
    metrics[OP_NUMBER] = {2, 0, 1, regular};
    metrics[OP_DIFFICULTY] = {2, 0, 1, regular};
    metrics[OP_GASLIMIT] = {2, 0, 1, regular};
    metrics[OP_POP] = {2, 1, -1, regular};
    metrics[OP_MLOAD] = {3, 1, 0, regular};
    metrics[OP_MSTORE] = {3, 2, -2, regular};
    metrics[OP_MSTORE8] = {3, 2, -2, regular};
    metrics[OP_SLOAD] = {50, 1, 0, regular};
    metrics[OP_SSTORE] = {0, 2, -2, regular};
    metrics[OP_JUMP] = {8, 1, -1, terminator};
    metrics[OP_JUMPI] = {10, 2, -2, terminator};
    metrics[OP_PC] = {2, 0, 1, pc};
    metrics[OP_MSIZE] = {2, 0, 1, regular};
    metrics[OP_GAS] = {2, 0, 1, gas_counter_user};
    metrics[OP_JUMPDEST] = {1, 0, 0, regular};

    for (size_t op = OP_PUSH1; op <= OP_PUSH8; ++op)
        metrics[op] = {3, 0, 1, small_push};

    for (size_t op = OP_PUSH9; op <= OP_PUSH32; ++op)
        metrics[op] = {3, 0, 1, large_push};

    for (size_t op = OP_DUP1; op <= OP_DUP16; ++op)
        metrics[op] = {3, int8_t(op - OP_DUP1 + 1), 1, regular};

    for (size_t op = OP_SWAP1; op <= OP_SWAP16; ++op)
        metrics[op] = {3, int8_t(op - OP_SWAP1 + 2), 0, regular};

    // FIXME: Use loop?
    metrics[OP_LOG0] = {1 * 375, 2, -2, regular};
    metrics[OP_LOG1] = {2 * 375, 3, -3, regular};
    metrics[OP_LOG2] = {3 * 375, 4, -4, regular};
    metrics[OP_LOG3] = {4 * 375, 5, -5, regular};
    metrics[OP_LOG4] = {5 * 375, 6, -6, regular};

    metrics[OP_CREATE] = {32000, 3, -2, gas_counter_user};
    metrics[OP_CALL] = {40, 7, -6, gas_counter_user};
    metrics[OP_CALLCODE] = {40, 7, -6, gas_counter_user};
    metrics[OP_RETURN] = {0, 2, -2, terminator};
    metrics[OP_INVALID] = {0, 0, 0, regular};
    metrics[OP_SELFDESTRUCT] = {0, 1, -1, terminator};

    return metrics;
}

constexpr metrics_table build_homestead_metrics() noexcept
{
    auto metrics = build_frontier_metrics();
    metrics[OP_DELEGATECALL] = {40, 6, -5, gas_counter_user};
    return metrics;
}

constexpr metrics_table build_tangerine_whistle_metrics() noexcept
{
    auto metrics = build_homestead_metrics();
    metrics[OP_BALANCE].gas_cost = 400;
    metrics[OP_EXTCODESIZE].gas_cost = 700;
    metrics[OP_EXTCODECOPY].gas_cost = 700;
    metrics[OP_SLOAD].gas_cost = 200;
    metrics[OP_CALL].gas_cost = 700;
    metrics[OP_CALLCODE].gas_cost = 700;
    metrics[OP_DELEGATECALL].gas_cost = 700;
    metrics[OP_SELFDESTRUCT].gas_cost = 5000;
    return metrics;
}

constexpr metrics_table build_byzantium_metrics() noexcept
{
    auto metrics = build_tangerine_whistle_metrics();
    metrics[OP_RETURNDATASIZE] = {2, 0, 1, regular};
    metrics[OP_RETURNDATACOPY] = {3, 3, -3, regular};
    metrics[OP_STATICCALL] = {700, 6, -5, gas_counter_user};
    metrics[OP_REVERT] = {0, 2, -2, terminator};
    return metrics;
}

constexpr metrics_table build_constantinople_metrics() noexcept
{
    auto metrics = build_byzantium_metrics();
    metrics[OP_SHL] = {3, 2, -1, regular};
    metrics[OP_SHR] = {3, 2, -1, regular};
    metrics[OP_SAR] = {3, 2, -1, regular};
    metrics[OP_EXTCODEHASH] = {400, 1, 0, regular};
    metrics[OP_CREATE2] = {32000, 4, -3, gas_counter_user};
    return metrics;
}
}  // namespace

// TODO: Return const metrics_table& ?
const instruction_metrics* get_metrics(evmc_revision rev) noexcept
{
    static constexpr metrics_table selector[] = {
        build_frontier_metrics(),
        build_homestead_metrics(),
        build_tangerine_whistle_metrics(),
        build_tangerine_whistle_metrics(),
        build_byzantium_metrics(),
        build_constantinople_metrics(),
        build_constantinople_metrics(),
        build_constantinople_metrics(),
    };
    static_assert(
        sizeof(selector) / sizeof(selector[0]) == EVMC_MAX_REVISION + 1, "missing metrics");
    return selector[rev].data();
}
}  // namespace evmone
