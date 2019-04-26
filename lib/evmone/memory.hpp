#pragma once

#include <stdint.h>
#include <stddef.h>

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

size_t get_num_memory_pages() noexcept;
memory_page get_current_memory_page() noexcept;
size_t map_gas_to_memory_ceiling(int64_t available_gas) noexcept;

// Call this method to get a pointer to a block of zeroed-out memory, whose size is large
// enough to contain any memory index that will not trigger an out of gas error
uint8_t* get_tx_memory_ptr(size_t available_gas) noexcept;

// Method is called when a transaction makes an external contract call.
// We need to update how much memory this transaction has used, so that the child
// transaction can get a pointer to unused memory
void stash_free_memory(size_t msize) noexcept;

// We call this when control flow returns to a transaction, after an external call.
// We assume that the external call has called memory::clean_up, so we know that the
// subsequent memory in the memory page is zeroed out
void restore_free_memory() noexcept;
// Clean up after a transaction.
// If the current memory page points has no allocated memory, and we have more than one
// memory page, decrease # of memory pages by one
void clean_up(size_t msize) noexcept;
}  // namespace memory
}  // namespace evmone