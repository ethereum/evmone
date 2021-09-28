// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <string>
#include <vector>

namespace evmone
{
struct AdvancedCodeAnalysis;
namespace baseline
{
struct CodeAnalysis;
}

using uint256 = intx::uint256;
using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;


/// The stack for 256-bit EVM words.
///
/// This implementation reserves memory inplace for all possible stack items (1024),
/// so this type is big. Make sure it is allocated on heap.
struct Stack
{
    /// The maximum number of stack items.
    static constexpr auto limit = 1024;

    /// The pointer to the top item, or below the stack bottom if stack is empty.
    intx::uint256* top_item;

    /// The storage allocated for maximum possible number of items.
    /// This is also the pointer to the bottom item.
    /// Items are aligned to 256 bits for better packing in cache lines.
    alignas(sizeof(intx::uint256)) intx::uint256 storage[limit];

    /// Default constructor. Sets the top_item pointer to below the stack bottom.
    Stack() noexcept { clear(); }

    /// The current number of items on the stack.
    [[nodiscard]] int size() const noexcept { return static_cast<int>(top_item + 1 - storage); }

    /// Returns the reference to the top item.
    [[nodiscard]] intx::uint256& top() noexcept { return *top_item; }

    /// Returns the reference to the stack item on given position from the stack top.
    [[nodiscard]] intx::uint256& operator[](int index) noexcept { return *(top_item - index); }

    /// Returns the const reference to the stack item on given position from the stack top.
    [[nodiscard]] const intx::uint256& operator[](int index) const noexcept
    {
        return *(top_item - index);
    }

    /// Pushes an item on the stack. The stack limit is not checked.
    void push(const intx::uint256& item) noexcept { *++top_item = item; }

    /// Returns an item popped from the top of the stack.
    intx::uint256 pop() noexcept { return *top_item--; }

    /// Clears the stack by resetting its size to 0 (sets the top_item pointer to below the stack
    /// bottom).
    [[clang::no_sanitize("bounds")]] void clear() noexcept { top_item = storage - 1; }
};

/// The EVM memory.
///
/// The implementations uses initial allocation of 4k and then grows capacity with 2x factor.
/// Some benchmarks has been done to confirm 4k is ok-ish value.
class Memory
{
    /// The size of allocation "page".
    static constexpr size_t page_size = 4 * 1024;

    /// Pointer to allocated memory.
    uint8_t* m_data = nullptr;

    /// The "virtual" size of the memory.
    size_t m_size = 0;

    /// The size of allocated memory. The initialization value is the initial capacity.
    size_t m_capacity = page_size;

public:
    /// Creates Memory object with initial capacity allocation.
    Memory() noexcept { m_data = static_cast<uint8_t*>(std::malloc(m_capacity)); }

    /// Frees all allocated memory.
    ~Memory() noexcept { std::free(m_data); }

    Memory(const Memory&) = delete;
    Memory& operator=(const Memory&) = delete;

    uint8_t& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] const uint8_t* data() const noexcept { return m_data; }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    /// Grows the memory to the given size. The extend is filled with zeros.
    ///
    /// @param new_size  New memory size. Must be larger than the current size and multiple of 32.
    void grow(size_t new_size) noexcept
    {
        // Restriction for future changes. EVM always has memory size as multiple of 32 bytes.
        assert(new_size % 32 == 0);

        // Allow only growing memory. Include hint for optimizing compiler.
        assert(new_size > m_size);
        if (new_size <= m_size)
            INTX_UNREACHABLE();

        if (new_size > m_capacity)
        {
            m_capacity *= 2;  // Double the capacity.

            if (m_capacity < new_size)  // If not enough.
            {
                // Set capacity to required size rounded to multiple of page_size.
                m_capacity = ((new_size + (page_size - 1)) / page_size) * page_size;
            }

            m_data = static_cast<uint8_t*>(std::realloc(m_data, m_capacity));
        }
        std::memset(m_data + m_size, 0, new_size - m_size);
        m_size = new_size;
    }

    /// Virtually clears the memory by setting its size to 0. The capacity stays unchanged.
    void clear() noexcept { m_size = 0; }
};

/// Generic execution state for generic instructions implementations.
struct ExecutionState
{
    int64_t gas_left = 0;
    Stack stack;
    Memory memory;
    const evmc_message* msg = nullptr;
    evmc::HostContext host;
    evmc_revision rev = {};
    bytes return_data;

    /// Reference to original EVM code.
    /// TODO: Code should be accessed via code analysis only and this should be removed.
    bytes_view code;

    evmc_status_code status = EVMC_SUCCESS;
    size_t output_offset = 0;
    size_t output_size = 0;

    /// Pointer to code analysis.
    /// This should be set and used internally by execute() function of a particular interpreter.
    union
    {
        const baseline::CodeAnalysis* baseline = nullptr;
        const AdvancedCodeAnalysis* advanced;
    } analysis{};

    ExecutionState() noexcept = default;

    ExecutionState(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        const uint8_t* code_ptr, size_t code_size) noexcept
      : gas_left{message.gas},
        msg{&message},
        host{host_interface, host_ctx},
        rev{revision},
        code{code_ptr, code_size}
    {}

    /// Resets the contents of the ExecutionState so that it could be reused.
    void reset(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        const uint8_t* code_ptr, size_t code_size) noexcept
    {
        gas_left = message.gas;
        stack.clear();
        memory.clear();
        msg = &message;
        host = {host_interface, host_ctx};
        rev = revision;
        return_data.clear();
        code = {code_ptr, code_size};
        status = EVMC_SUCCESS;
        output_offset = 0;
        output_size = 0;
    }
};
}  // namespace evmone
