// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <assert.h>
#include <test/utils/bytecode.hpp>
#include <set>
#include <vector>

namespace evmmax::evm::utils
{
struct Scope;

struct SlotRegister
{
private:
    friend struct Scope;

    std::vector<bool> vals;

    [[nodiscard]] uint8_t new_slot() noexcept
    {
        if (const auto it = std::find(vals.begin(), vals.end(), false); it != vals.end())
        {
            *it = true;
            return static_cast<uint8_t>(std::distance(vals.begin(), it));
        }
        else
        {
            assert(vals.size() < 256);
            vals.push_back(true);
            return static_cast<uint8_t>(vals.size() - 1);
        }
    }

    void free_slot(uint8_t slot_idx) noexcept
    {
        if (slot_idx < vals.size())
            vals[slot_idx] = false;
        else
            assert(false);  // Invalid slot idx
    }

public:
    explicit SlotRegister() noexcept
    {
        // Assumption that slot 0 keeps value 0 and slot 1 keeps value 1 (in Montgomery form).
        // Never write to these slots.
        (void)new_slot();
        (void)new_slot();
    }
    [[nodiscard]] uint8_t max_slots_used() const { return static_cast<uint8_t>(vals.size()); }
};

struct Scope
{
private:
    std::set<uint8_t> slots;
    SlotRegister& slot_register;

public:
    explicit Scope(SlotRegister& reg) noexcept : slot_register(reg) {}
    explicit Scope(const Scope& outer_scope) noexcept : slot_register(outer_scope.slot_register) {}

    [[nodiscard]] uint8_t new_slot() noexcept
    {
        const auto new_slot = slot_register.new_slot();
        slots.insert(new_slot);
        return new_slot;
    }

    virtual ~Scope() noexcept
    {
        for (const auto& slot : slots)
            slot_register.free_slot(slot);
    }
};

template <size_t N>
[[nodiscard]] bytecode copy_values(uint8_t const (&inputs)[N], uint8_t const (&outputs)[N])
{
    // Slot 0 stores 0 value by convention.
    auto code = bytecode{};

    for (size_t i = 0; i < N; ++i)
    {
        if (inputs[i] != outputs[i])
            code += addmodx(outputs[i], inputs[i], 0);
    }

    return code;
}

[[nodiscard]] inline bytecode copy_values(uint8_t input_idx, uint8_t output_idx) noexcept
{
    return input_idx != output_idx ? addmodx(output_idx, input_idx, 0) : bytecode{};
}


}  // namespace evmmax::evm::utils
