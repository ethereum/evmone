// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <exception>
#include <memory>
#include <string>
#include <vector>

namespace evmone
{
namespace advanced
{
struct AdvancedCodeAnalysis;
}
namespace baseline
{
class CodeAnalysis;
}

using evmc::bytes;
using evmc::bytes_view;
using intx::uint256;


/// Provides memory for EVM stack.
class StackSpace
{
    static uint256* allocate() noexcept
    {
        static constexpr auto alignment = sizeof(uint256);
        static constexpr auto size = limit * sizeof(uint256);
#ifdef _MSC_VER
        // MSVC doesn't support aligned_alloc() but _aligned_malloc() can be used instead.
        const auto p = _aligned_malloc(size, alignment);
#else
        const auto p = std::aligned_alloc(alignment, size);
#endif
        return static_cast<uint256*>(p);
    }

    struct Deleter
    {
        // TODO(C++23): static
        void operator()(void* p) noexcept
        {
#ifdef _MSC_VER
            // For MSVC the _aligned_malloc() must be paired with _aligned_free().
            _aligned_free(p);
#else
            std::free(p);
#endif
        }
    };

    /// The storage allocated for maximum possible number of items.
    /// Items are aligned to 256 bits for better packing in cache lines.
    std::unique_ptr<uint256, Deleter> m_stack_space;

public:
    /// The maximum number of EVM stack items.
    static constexpr auto limit = 1024;

    StackSpace() noexcept : m_stack_space{allocate()} {}

    /// Returns the pointer to the "bottom", i.e. below the stack space.
    [[nodiscard]] uint256* bottom() noexcept { return m_stack_space.get(); }
};


/// The EVM memory.
///
/// The implementations uses initial allocation of 4k and then grows capacity with 2x factor.
/// Some benchmarks have been done to confirm 4k is ok-ish value.
class Memory
{
    /// The size of allocation "page".
    static constexpr size_t page_size = 4 * 1024;

    struct FreeDeleter
    {
        void operator()(uint8_t* p) const noexcept { std::free(p); }
    };

    /// Owned pointer to allocated memory.
    std::unique_ptr<uint8_t[], FreeDeleter> m_data;

    /// The "virtual" size of the memory.
    size_t m_size = 0;

    /// The size of allocated memory. The initialization value is the initial capacity.
    size_t m_capacity = page_size;

    [[noreturn, gnu::cold]] static void handle_out_of_memory() noexcept { std::terminate(); }

    void allocate_capacity() noexcept
    {
        m_data.reset(static_cast<uint8_t*>(std::realloc(m_data.release(), m_capacity)));
        if (!m_data) [[unlikely]]
            handle_out_of_memory();
    }

public:
    /// Creates Memory object with initial capacity allocation.
    Memory() noexcept { allocate_capacity(); }

    uint8_t& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] const uint8_t* data() const noexcept { return m_data.get(); }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    /// Grows the memory to the given size. The extent is filled with zeros.
    ///
    /// @param new_size  New memory size. Must be larger than the current size and multiple of 32.
    void grow(size_t new_size) noexcept
    {
        // Restriction for future changes. EVM always has memory size as multiple of 32 bytes.
        INTX_REQUIRE(new_size % 32 == 0);

        // Allow only growing memory. Include hint for optimizing compiler.
        INTX_REQUIRE(new_size > m_size);

        if (new_size > m_capacity)
        {
            m_capacity *= 2;  // Double the capacity.

            if (m_capacity < new_size)  // If not enough.
            {
                // Set capacity to required size rounded to multiple of page_size.
                m_capacity = ((new_size + (page_size - 1)) / page_size) * page_size;
            }

            allocate_capacity();
        }
        std::memset(&m_data[m_size], 0, new_size - m_size);
        m_size = new_size;
    }

    /// Virtually clears the memory by setting its size to 0. The capacity stays unchanged.
    void clear() noexcept { m_size = 0; }
};

/// Initcode read from Initcode Transaction (EIP-7873).
struct TransactionInitcode
{
    /// Initcode bytes.
    bytes_view code;
    /// Result of initcode validation, if it was validated.
    /// std::nullopt if initcode was not validated yet.
    std::optional<bool> is_valid;
};

/// Generic execution state for generic instructions implementations.
// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding)
class ExecutionState
{
public:
    int64_t gas_refund = 0;
    Memory memory;
    const evmc_message* msg = nullptr;
    evmc::HostContext host;
    evmc_revision rev = {};
    bytes return_data;

    /// Reference to original EVM code container.
    /// For legacy code this is a reference to entire original code.
    /// For EOF-formatted code this is a reference to entire container.
    bytes_view original_code;

    evmc_status_code status = EVMC_SUCCESS;
    size_t output_offset = 0;
    size_t output_size = 0;

    /// Container to be deployed returned from RETURNCODE, used only inside EOFCREATE execution.
    std::optional<bytes> deploy_container;

private:
    evmc_tx_context m_tx = {};
    std::optional<std::unordered_map<evmc::bytes32, TransactionInitcode>> m_initcodes;

public:
    /// Pointer to code analysis.
    /// This should be set and used internally by execute() function of a particular interpreter.
    union
    {
        const baseline::CodeAnalysis* baseline = nullptr;
        const advanced::AdvancedCodeAnalysis* advanced;
    } analysis{};

    std::vector<const uint8_t*> call_stack;

    /// Stack space allocation.
    ///
    /// This is the last field to make other fields' offsets of reasonable values.
    StackSpace stack_space;

    ExecutionState() noexcept = default;

    ExecutionState(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        bytes_view _code) noexcept
      : msg{&message}, host{host_interface, host_ctx}, rev{revision}, original_code{_code}
    {}

    /// Resets the contents of the ExecutionState so that it could be reused.
    void reset(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        bytes_view _code) noexcept
    {
        gas_refund = 0;
        memory.clear();
        msg = &message;
        host = {host_interface, host_ctx};
        rev = revision;
        return_data.clear();
        original_code = _code;
        status = EVMC_SUCCESS;
        output_offset = 0;
        output_size = 0;
        deploy_container = {};
        m_tx = {};
        m_initcodes.reset();
        call_stack = {};
    }

    [[nodiscard]] bool in_static_mode() const { return (msg->flags & EVMC_STATIC) != 0; }

    const evmc_tx_context& get_tx_context() noexcept
    {
        if (INTX_UNLIKELY(m_tx.block_timestamp == 0))
            m_tx = host.get_tx_context();
        return m_tx;
    }

    /// Get initcode by its hash from transaction initcodes.
    ///
    /// Returns nullptr if no such initcode was found.
    [[nodiscard]] TransactionInitcode* get_tx_initcode_by_hash(const evmc_bytes32& hash)
    {
        if (!m_initcodes.has_value())
        {
            m_initcodes.emplace();
            const auto& tx_context = get_tx_context();
            for (size_t i = 0; i < tx_context.initcodes_count; ++i)
            {
                const auto& initcode = tx_context.initcodes[i];
                m_initcodes->insert({initcode.hash,
                    {.code = {initcode.code, initcode.code_size}, .is_valid = std::nullopt}});
            }
        }

        const auto it = m_initcodes->find(hash);
        return it != m_initcodes->end() ? &it->second : nullptr;
    }
};
}  // namespace evmone
