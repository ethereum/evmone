#pragma once

#include "constants.hpp"

#include <math.h>
#include <memory.h>
#include <stdint.h>

namespace evmone
{
namespace memory
{
struct memory_page
{
    uint8_t* pointer;
    size_t allocated_memory;
    size_t max_memory;
    size_t stashed_free_memory;
};

namespace
{
size_t num_memory_pages = 0;
memory_page** memory_ptrs = nullptr;
memory_page* current_memory = nullptr;

// internal method, called to create a new memory page
void allocate_memory(size_t required_memory) noexcept
{
    // we need to reallocate memory_ptrs
    num_memory_pages++;
    memory_ptrs =
        static_cast<memory_page**>(realloc(memory_ptrs, sizeof(memory_page**) * num_memory_pages));
    size_t max_memory =
        required_memory > BASE_MEMORY_POOL_SIZE ? required_memory : BASE_MEMORY_POOL_SIZE;
    uint8_t* new_memory_pointer = static_cast<uint8_t*>(calloc(max_memory, sizeof(uint8_t)));
    // memory_ptrs is a dynamic array of memory structs
    // so the pointer points to the first element of one of these structs
    memory_ptrs[num_memory_pages - 1] = new (std::nothrow) memory_page{
        .pointer = new_memory_pointer,
        .allocated_memory = 0,
        .max_memory = max_memory,
        .stashed_free_memory = 0,
    };
    current_memory = memory_ptrs[num_memory_pages - 1];
}
};  // namespace

size_t get_num_memory_pages() noexcept
{
    return num_memory_pages;
}

memory_page get_current_memory_page() noexcept
{
    memory_page current_memory_page = {
        .pointer = current_memory->pointer,
        .allocated_memory = current_memory->allocated_memory,
        .max_memory = current_memory->max_memory,
        .stashed_free_memory = current_memory->stashed_free_memory,
    };
    return current_memory_page;
}

size_t map_gas_to_memory_ceiling(int64_t available_gas) noexcept
{
        // gas formula = 3*w + ((w * w) / 512)
        // => maximum memory (in words) that can be reached by g = 'available gas' is
        //           0 = 1536*w + w*w - 512*g
        // ~ w = sqrt(2359296 + 2048 * g) / 2
        // we ignore a small negative factor in the quadratic formula, to prevent 'max_tx_words'
        // turning negative from rounding errors
        size_t max_tx_words =
        std::sqrt(static_cast<long double>(2359296 + 2048 * static_cast<long double>(available_gas))) / 2;
        size_t max_tx_bytes = max_tx_words * 32;

        return max_tx_bytes + 32;
 
        // N.B. This code enforces that allocated memory is equal to a power of 2, minus 1.
        // This enables memory indices to be efficiently pinned via a logical AND statement.
        // This in turn makes it possible to defer gas accounting for memory reads/writes, as it is no longer
        // possible to write to memory that is out of bounds.
        // However...performing gas accounting per basic block was less performant
        // than just performing the computation when required.
        // (maybe using this in conjunction with running gas accounting in a second, non-blocking thread would be faster?)
        // size_t leading_zeroes = 0;
        // if (sizeof(size_t) == sizeof(unsigned long long))
        // {
        //     leading_zeroes = __builtin_clzll(max_tx_bytes);
        // }
        // else if (sizeof(size_t) == sizeof(unsigned long))
        // {
        //     leading_zeroes = __builtin_clzl(max_tx_bytes);
        // }
        // else
        // {
        //     leading_zeroes = __builtin_clz(max_tx_bytes);
        // }
        // size_t tx_allocated_memory =
        //     static_cast<size_t>((static_cast<size_t>(~0) >> leading_zeroes)) + 32;
}

// Call this method to get a pointer to a block of zeroed-out memory, whose size is large
// enough to contain any memory index that will not trigger an out of gas error
uint8_t* get_tx_memory_ptr(size_t available_gas) noexcept
{
    if (current_memory == nullptr)
    {
        allocate_memory(BASE_MEMORY_POOL_SIZE);
    }

    size_t tx_allocated_memory = map_gas_to_memory_ceiling(available_gas); // (max_tx_words * 32);

    if (tx_allocated_memory + current_memory->allocated_memory > current_memory->max_memory)
    {
        allocate_memory(tx_allocated_memory);
    }
    if (current_memory == nullptr)
    {
        return nullptr;
    }
    uint8_t* tx_memory_ptr = current_memory->pointer + current_memory->allocated_memory;
    return tx_memory_ptr;
}

// Method is called when a transaction makes an external contract call.
// We need to update how much memory this transaction has used, so that the child
// transaction can get a pointer to unused memory
void stash_free_memory(size_t msize) noexcept
{
    memory_page& current_memory_page = *current_memory;
    current_memory_page.allocated_memory += msize;
    current_memory_page.stashed_free_memory = msize;
}

// We call this when control flow returns to a transaction, after an external call.
// We assume that the external call has called memory::clean_up, so we know that the
// subsequent memory in the memory page is zeroed out
void restore_free_memory() noexcept
{
    memory_page& current_memory_page = *current_memory;
    current_memory_page.allocated_memory -= current_memory_page.stashed_free_memory;
    current_memory_page.stashed_free_memory = 0;
}

// Clean up after a transaction.
// If the current memory page points has no allocated memory, and we have more than one
// memory page, decrease # of memory pages by one
void clean_up(size_t msize) noexcept
{
    if (current_memory->allocated_memory > 0)
    {
    }
    if (current_memory->allocated_memory == 0 && num_memory_pages > 1)
    {
        free(current_memory->pointer);
        num_memory_pages--;
        free(memory_ptrs[num_memory_pages]);
        current_memory = memory_ptrs[num_memory_pages - 1];
    }
    else
    {
        // We only have 1 memory page, so we should preserve this one instead of destroying it
        memory_page& current_memory_page = *current_memory;

        // Zero memory between allocated memory and allocated memory + msize
        // current_memory persists beyond the scope of this function, so the compiler shouldn't optimize this out!
        memset(current_memory_page.pointer + current_memory_page.allocated_memory, 0, msize * sizeof(uint8_t));
    }
}
}  // namespace memory
}  // namespace evmone