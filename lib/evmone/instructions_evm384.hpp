#pragma once

#include "instructions.hpp"
#include "mulx_mont_384.h"

#define BIGINT_BITS 384
#define LIMB_BITS 64
#define LIMB_BITS_OVERFLOW 128
#include "bigint.h"
#undef BIGINT_BITS
#undef LIMB_BITS
#undef LIMB_BITS_OVERFLOW

namespace evmone
{
inline evmc_status_code addmod384(ExecutionState& state) noexcept
{
    const auto arg = state.stack.pop();
    const auto params = intx::as_bytes(arg);


    const auto out_offset = *reinterpret_cast<const uint32_t*>(&params[12]);
    const auto x_offset = *reinterpret_cast<const uint32_t*>(&params[8]);
    const auto y_offset = *reinterpret_cast<const uint32_t*>(&params[4]);
    const auto mod_offset = *reinterpret_cast<const uint32_t*>(&params[0]);

    const auto max_memory_index =
        std::max(std::max(x_offset, y_offset), std::max(out_offset, mod_offset));

    if (!check_memory(state, max_memory_index, 48))
        return EVMC_OUT_OF_GAS;

    const auto out = &state.memory[static_cast<size_t>(out_offset)];
    const auto x = &state.memory[static_cast<size_t>(x_offset)];
    const auto y = &state.memory[static_cast<size_t>(y_offset)];
    const auto m = &state.memory[static_cast<size_t>(mod_offset)];

    addmod384_64bitlimbs(reinterpret_cast<uint64_t*>(out), reinterpret_cast<uint64_t*>(x),
        reinterpret_cast<uint64_t*>(y), reinterpret_cast<uint64_t*>(m));

    return EVMC_SUCCESS;
}

inline evmc_status_code submod384(ExecutionState& state) noexcept
{
    const auto params = intx::as_bytes(state.stack[0]);
    state.stack.pop();

    const auto out_offset = *reinterpret_cast<const uint32_t*>(&params[12]);
    const auto x_offset = *reinterpret_cast<const uint32_t*>(&params[8]);
    const auto y_offset = *reinterpret_cast<const uint32_t*>(&params[4]);
    const auto mod_offset = *reinterpret_cast<const uint32_t*>(&params[0]);

    const auto max_memory_index =
        std::max(std::max(x_offset, y_offset), std::max(out_offset, mod_offset));

    if (!check_memory(state, max_memory_index, 48))
        return EVMC_OUT_OF_GAS;

    const auto out = &state.memory[static_cast<size_t>(out_offset)];
    const auto x = &state.memory[static_cast<size_t>(x_offset)];
    const auto y = &state.memory[static_cast<size_t>(y_offset)];
    const auto m = &state.memory[static_cast<size_t>(mod_offset)];

    subtractmod384_64bitlimbs(reinterpret_cast<uint64_t*>(out), reinterpret_cast<uint64_t*>(x),
        reinterpret_cast<uint64_t*>(y), reinterpret_cast<uint64_t*>(m));

    return EVMC_SUCCESS;
}

inline evmc_status_code mulmodmont384(ExecutionState& state) noexcept
{
    const auto params = intx::as_bytes(state.stack[0]);
    state.stack.pop();

    const auto out_offset = *reinterpret_cast<const uint32_t*>(&params[12]);
    const auto x_offset = *reinterpret_cast<const uint32_t*>(&params[8]);
    const auto y_offset = *reinterpret_cast<const uint32_t*>(&params[4]);
    const auto mod_offset = *reinterpret_cast<const uint32_t*>(&params[0]);

    const auto max_memory_index =
        std::max(std::max(x_offset, y_offset), std::max(out_offset, mod_offset));

    // TODO only expand memory by 56 bytes if mod/inv is out of the bounds
    if (!check_memory(state, max_memory_index, 56))
        return EVMC_OUT_OF_GAS;

    const auto out = reinterpret_cast<uint64_t*>(&state.memory[static_cast<size_t>(out_offset)]);
    const auto x = reinterpret_cast<uint64_t*>(&state.memory[static_cast<size_t>(x_offset)]);
    const auto y = reinterpret_cast<uint64_t*>(&state.memory[static_cast<size_t>(y_offset)]);
    const auto m = reinterpret_cast<uint64_t*>(&state.memory[static_cast<size_t>(mod_offset)]);
    const uint64_t inv = *reinterpret_cast<const uint64_t*>(&state.memory[mod_offset + 48]);

#ifndef USE_ASM
#define USE_ASM 1
#endif

#if USE_ASM
    mulx_mont_384(out, x, y, m, inv);
#else
    montmul384_64bitlimbs(out, x, y, m, inv);
#endif

    return EVMC_SUCCESS;
}
}  // namespace evmone
