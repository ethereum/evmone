// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "synthetic_benchmarks.hpp"
#include "helpers.hpp"
#include "test/utils/bytecode.hpp"
#include <evmc/instructions.h>
#include <evmone/instruction_traits.hpp>

using namespace benchmark;

namespace evmone::test
{
namespace
{
/// Stack limit inside the EVM benchmarking loop (one stack item is used for the loop count).
constexpr auto stack_limit = 1023;

enum class Mode
{
    min_stack = 0,   ///< The code uses as minimal stack as possible.
    full_stack = 1,  ///< The code fills the stack up to its limit.
};

enum class InstructionKind : char
{
    nullop = 'n',
    unop = 'u',
    binop = 'b',
    push = 'p',
    producer = 'a',
    unknown = 'X',
};

constexpr InstructionKind get_instruction_kind(evmc_opcode opcode) noexcept
{
    const auto trait = instr::traits[opcode];
    if (opcode >= OP_PUSH1 && opcode <= OP_PUSH32)
        return InstructionKind::push;
    else if (trait.stack_height_required == 0 && trait.stack_height_change == 0)
        return InstructionKind::nullop;
    else if (trait.stack_height_required == 1 && trait.stack_height_change == 0)
        return InstructionKind::unop;
    else if (trait.stack_height_required == 2 && trait.stack_height_change == -1)
        return InstructionKind::binop;
    else if (trait.stack_height_required == 0 && trait.stack_height_change == 1)
        return InstructionKind::producer;
    else
        return InstructionKind::unknown;
}

struct CodeParams
{
    evmc_opcode opcode;
    Mode mode;
};

inline constexpr bool operator<(const CodeParams& a, const CodeParams& b) noexcept
{
    return std::tuple(a.opcode, a.mode) < std::tuple(b.opcode, b.mode);
}

std::string to_string(const CodeParams& params)
{
    return std::string{instr::traits[params.opcode].name} + '/' +
           static_cast<char>(get_instruction_kind(params.opcode)) +
           std::to_string(static_cast<int>(params.mode));
}

/// Generates the EVM benchmarking loop inner code for the given opcode and "mode".
bytecode generate_loop_inner_code(CodeParams params)
{
    const auto [opcode, mode] = params;
    const auto kind = get_instruction_kind(opcode);
    switch (mode)
    {
    case Mode::min_stack:
        switch (kind)
        {
        case InstructionKind::push:
            return stack_limit * (push(opcode, {}) + OP_POP);
        case InstructionKind::producer:
            return stack_limit * (bytecode{opcode} + OP_POP);
        case InstructionKind::nullop:
            return stack_limit * 2 * bytecode{opcode};
        case InstructionKind::unop:
            return OP_DUP1 + stack_limit * 2 * bytecode{opcode} + OP_POP;
        case InstructionKind::binop:
            return OP_DUP1 + (stack_limit - 1) * (OP_DUP1 + bytecode{opcode}) + OP_POP;
        default:
            INTX_UNREACHABLE();
        }
    case Mode::full_stack:
        switch (kind)
        {
        case InstructionKind::push:
            return stack_limit * push(opcode, {}) + stack_limit * OP_POP;
        case InstructionKind::producer:
            return stack_limit * opcode + stack_limit * OP_POP;
        case InstructionKind::binop:
            return stack_limit * OP_DUP1 + (stack_limit - 1) * opcode + OP_POP;
        default:
            INTX_UNREACHABLE();
        }
    default:
        INTX_UNREACHABLE();
    }

    return {};  // Make old compilers happy.
}


const auto loop_prefix = push(255) + OP_JUMPDEST;
const auto loop_suffix = push("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") +
                         OP_ADD + OP_DUP1 + push(2) + OP_JUMPI;

bytes_view generate_code(CodeParams params)
{
    static std::map<CodeParams, bytecode> cache;

    auto& code = cache[params];
    if (!code.empty())
        return code;

    code = loop_prefix + generate_loop_inner_code(params) + loop_suffix;  // Cache it.
    return code;
}
}  // namespace

void register_synthetic_benchmarks()
{
    std::vector<CodeParams> params_list;

    // Nullops & unops.
    for (const auto opcode : {OP_JUMPDEST, OP_ISZERO, OP_NOT})
        params_list.push_back({opcode, Mode::min_stack});

    // Binops.
    for (const auto opcode : {OP_ADD, OP_MUL, OP_SUB, OP_SIGNEXTEND, OP_LT, OP_GT, OP_SLT, OP_SGT,
             OP_EQ, OP_AND, OP_OR, OP_XOR, OP_BYTE, OP_SHL, OP_SHR, OP_SAR})
        params_list.insert(
            params_list.end(), {{opcode, Mode::min_stack}, {opcode, Mode::full_stack}});

    // Producers.
    for (const auto opcode : {OP_ADDRESS, OP_CALLER, OP_CALLVALUE, OP_CALLDATASIZE, OP_CODESIZE,
             OP_RETURNDATASIZE, OP_PC, OP_MSIZE, OP_GAS})
        params_list.insert(
            params_list.end(), {{opcode, Mode::min_stack}, {opcode, Mode::full_stack}});

    // PUSH.
    for (auto opcode = OP_PUSH1; opcode <= OP_PUSH32; opcode = static_cast<evmc_opcode>(opcode + 1))
        params_list.insert(
            params_list.end(), {{opcode, Mode::min_stack}, {opcode, Mode::full_stack}});


    for (auto& [vm_name, vm] : registered_vms)
    {
        RegisterBenchmark((std::string{vm_name} + "/execute/synth/loop").c_str(),
            [&vm = vm](State& state) {
                const auto code = loop_prefix + loop_suffix;
                execute(state, vm, code);
            })
            ->Unit(kMicrosecond);
    }

    for (const auto params : params_list)
    {
        for (auto& [vm_name, vm] : registered_vms)
        {
            RegisterBenchmark(
                (std::string{vm_name} + "/execute/synth/" + to_string(params)).c_str(),
                [&vm = vm, params](State& state) { execute(state, vm, generate_code(params)); })
                ->Unit(kMicrosecond);
        }
    }
}
}  // namespace evmone::test
