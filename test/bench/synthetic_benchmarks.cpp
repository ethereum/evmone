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

/// Generates the EVM benchmarking loop inner code for the given opcode and "mode".
bytecode generate_loop_inner_code(evmc_opcode opcode, Mode mode)
{
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

bytes_view generate_code(evmc_opcode opcode, Mode mode)
{
    static bytes cache[256][2]{};

    auto& code = cache[opcode][static_cast<int>(mode)];
    if (!code.empty())
        return code;

    code = loop_prefix + generate_loop_inner_code(opcode, mode) + loop_suffix;  // Cache it.
    return code;
}
}  // namespace

void register_synthetic_benchmarks()
{
    std::vector opcodes{OP_JUMPDEST,

        // binops:
        OP_ADD, OP_MUL, OP_SUB, OP_SIGNEXTEND, OP_LT, OP_GT, OP_SLT, OP_SGT, OP_EQ, OP_AND, OP_OR,
        OP_XOR, OP_BYTE, OP_SHL, OP_SHR, OP_SAR,

        // unops:
        OP_ISZERO, OP_NOT,

        // producers:
        OP_ADDRESS, OP_CALLER, OP_CALLVALUE, OP_CALLDATASIZE, OP_CODESIZE, OP_RETURNDATASIZE, OP_PC,
        OP_MSIZE, OP_GAS};

    for (int i = OP_PUSH1; i <= OP_PUSH32; ++i)
        opcodes.push_back(static_cast<evmc_opcode>(i));

    for (auto& [vm_name, vm] : registered_vms)
    {
        RegisterBenchmark((std::string{vm_name} + "/execute/synth/loop").c_str(),
            [&vm = vm](State& state) {
                const auto code = loop_prefix + loop_suffix;
                execute(state, vm, code);
            })
            ->Unit(kMicrosecond);
    }

    for (const auto opcode : opcodes)
    {
        const auto kind = get_instruction_kind(opcode);

        for (const auto mode : {Mode::min_stack, Mode::full_stack})
        {
            if (mode == Mode::full_stack &&
                (kind == InstructionKind::unop || kind == InstructionKind::nullop))
                continue;

            const auto name_suffix =
                std::string{'/', static_cast<char>(kind)} + std::to_string(static_cast<int>(mode));

            for (auto& [vm_name, vm] : registered_vms)
            {
                RegisterBenchmark((std::string{vm_name} + "/execute/synth/" +
                                      instr::traits[opcode].name + name_suffix)
                                      .c_str(),
                    [&vm = vm, opcode, mode](
                        State& state) { execute(state, vm, generate_code(opcode, mode)); })
                    ->Unit(kMicrosecond);
            }
        }
    }
}

}  // namespace evmone::test
