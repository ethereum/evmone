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
/// Stack limit inside the EVM benchmarking loop (one stack item is used for the loop counter).
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
    swap = 's',
    dup = 'd',
    producer = 'a',
    unknown = 'X',
};

constexpr InstructionKind get_instruction_kind(evmc_opcode opcode) noexcept
{
    const auto trait = instr::traits[opcode];
    if (opcode >= OP_PUSH1 && opcode <= OP_PUSH32)
        return InstructionKind::push;
    else if (opcode >= OP_SWAP1 && opcode <= OP_SWAP16)
        return InstructionKind::swap;
    else if (opcode >= OP_DUP1 && opcode <= OP_DUP16)
        return InstructionKind::dup;
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

/// The less-than comparison operator. Needed for std::map.
[[maybe_unused]] inline constexpr bool operator<(const CodeParams& a, const CodeParams& b) noexcept
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
            // PUSH1 POP PUSH1 POP ...
            return stack_limit * (push(opcode, {}) + OP_POP);
        case InstructionKind::swap:
        {
            const auto n = opcode - OP_SWAP1 + 1;
            // DUP1 SWAP1 SWAP1 ... POP
            return n * OP_DUP1 + stack_limit * 2 * bytecode{opcode} + n * OP_POP;
        }
        case InstructionKind::dup:
        {
            const auto n = opcode - OP_DUP1;
            // DUP1 DUP1 POP DUP1 POP ... POP
            return n * OP_DUP1 + (stack_limit - n) * (bytecode{opcode} + OP_POP) + n * OP_POP;
        }
        case InstructionKind::producer:
            // CALLER POP CALLER POP ...
            return stack_limit * (bytecode{opcode} + OP_POP);
        case InstructionKind::nullop:
            // JUMPDEST JUMPDEST ...
            return stack_limit * 2 * bytecode{opcode};
        case InstructionKind::unop:
            // DUP1 NOT NOT ... POP
            return OP_DUP1 + stack_limit * 2 * bytecode{opcode} + OP_POP;
        case InstructionKind::binop:
            // DUP1 DUP1 ADD DUP1 ADD DUP1 ADD ... POP
            return OP_DUP1 + (stack_limit - 1) * (OP_DUP1 + bytecode{opcode}) + OP_POP;
        default:
            break;
        }
        break;
    case Mode::full_stack:
        switch (kind)
        {
        case InstructionKind::push:
            // PUSH1 PUSH1 PUSH1 ... POP POP POP ...
            return stack_limit * push(opcode, {}) + stack_limit * OP_POP;
        case InstructionKind::dup:
        {
            const auto n = opcode - OP_DUP1;
            // DUP1 DUP1 POP DUP1 POP ... POP
            return n * OP_DUP1 + (stack_limit - n) * bytecode{opcode} + stack_limit * OP_POP;
        }
        case InstructionKind::producer:
            // CALLER CALLER ... POP POP ...
            return stack_limit * opcode + stack_limit * OP_POP;
        case InstructionKind::binop:
            // DUP1 DUP1 DUP1 ... ADD ADD ADD ... POP
            return stack_limit * OP_DUP1 + (stack_limit - 1) * opcode + OP_POP;
        default:
            break;
        }
        break;
    }

    return {};
}

/// Generates a benchmarking loop with given inner code.
///
/// This generates do-while loop with 256 iterations and is starts with PUSH1 of 255 as the loop
/// counter. The while check is done as `(counter += -1) != 0`. The SUB is avoided because it
/// consumes arguments in unnatural order and additional SWAP would be required.
///
/// The loop counter stays on the stack top. The inner code is allowed to duplicate it, but must not
/// modify it.
bytecode generate_loop_v1(const bytecode& inner_code)
{
    return push(255) + OP_JUMPDEST + inner_code +
           push("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") + OP_ADD +
           OP_DUP1 + push(2) + OP_JUMPI;
}

/// Generates a benchmarking loop with given inner code.
///
/// This is improved variant of v1. It has exactly the same instructions and consumes the same
/// amount of gas, but according to performed benchmarks (see "loop_v1" and "loop_v2") it runs
/// faster. And we want the lowest possible loop overhead.
/// The change is to set the loop counter to -255 and check `(counter += 1) != 0`.
bytecode generate_loop_v2(const bytecode& inner_code)
{
    return push("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01") + OP_JUMPDEST +
           inner_code + push(1) + OP_ADD + OP_DUP1 + push(33) + OP_JUMPI;
}

bytes_view generate_code(CodeParams params)
{
    static std::map<CodeParams, bytecode> cache;

    auto& code = cache[params];
    if (!code.empty())
        return code;

    code = generate_loop_v2(generate_loop_inner_code(params));  // Cache it.
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

    // SWAP.
    for (auto opcode = OP_SWAP1; opcode <= OP_SWAP16; opcode = static_cast<evmc_opcode>(opcode + 1))
        params_list.insert(params_list.end(), {{opcode, Mode::min_stack}});

    // DUP.
    for (auto opcode = OP_DUP1; opcode <= OP_DUP16; opcode = static_cast<evmc_opcode>(opcode + 1))
        params_list.insert(
            params_list.end(), {{opcode, Mode::min_stack}, {opcode, Mode::full_stack}});


    for (auto& [vm_name, vm] : registered_vms)
    {
        RegisterBenchmark((std::string{vm_name} + "/execute/synth/loop_v1").c_str(),
            [&vm = vm](State& state) { execute(state, vm, generate_loop_v1({})); });
        RegisterBenchmark((std::string{vm_name} + "/execute/synth/loop_v2").c_str(),
            [&vm = vm](State& state) { execute(state, vm, generate_loop_v2({})); });
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
