#pragma once

#include <math.h>
#include <memory.h>
#include <stdint.h>

#include <iostream>

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

        const size_t BASE_MEMORY_POOL_SIZE = 0x4000000; // 64 MB

        namespace
        {
            size_t num_memory_pages = 0;
            memory_page** memory_ptrs = nullptr;
            memory_page* current_memory = nullptr;
        };

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

        void allocate_memory(size_t required_memory) noexcept
        {
            // we need to reallocate memory_ptrs
            num_memory_pages++;
            memory_ptrs = static_cast<memory_page**>(realloc(memory_ptrs, sizeof(memory_page**) * num_memory_pages));
            size_t max_memory = required_memory > BASE_MEMORY_POOL_SIZE ? required_memory : BASE_MEMORY_POOL_SIZE;
            uint8_t* new_memory_pointer = static_cast<uint8_t*>(calloc(max_memory, sizeof(uint8_t)));
            // memory_ptrs is a dynamic array of memory structs
            // so the pointer points to the first element of one of these structs
            memory_ptrs[num_memory_pages - 1] = new memory_page {
                .pointer = new_memory_pointer,
                .allocated_memory = 0,
                .max_memory = max_memory,
                .stashed_free_memory = 0,
                };
            current_memory = memory_ptrs[num_memory_pages - 1];
        }

        std::pair<uint8_t*, size_t> get_tx_memory_ptr(size_t available_gas) noexcept
        {
            if(current_memory == nullptr)
            {
                allocate_memory(BASE_MEMORY_POOL_SIZE);
            }
            size_t max_tx_words = std::sqrt(static_cast<double>(2359296 + 2048 * static_cast<double>(available_gas))) / 2;
            size_t max_tx_memory = (max_tx_words * 32);

            // We want the amount of allocated memory - 32 to be equal to a power of (2^n - 1).
            // This is so that, for memory opcodes, we can 'pin' the maximum memory index with a simple logical AND
            size_t tx_allocated_memory = static_cast<size_t>(((unsigned int)(~0) >> __builtin_clz(max_tx_memory)) + 32);
            if (tx_allocated_memory + current_memory->allocated_memory > current_memory->max_memory)
            {
                allocate_memory(tx_allocated_memory);
            }
            uint8_t* tx_memory_ptr = current_memory->pointer + current_memory->allocated_memory; // + tx_allocated_memory;
            return std::pair<uint8_t*, size_t>(tx_memory_ptr, tx_allocated_memory);
        }

        void stash_free_memory(size_t msize) noexcept
        {
            // Method is called when a transaction makes an external contract call.
            // We need to update how much memory this transaction has used, so that the child
            // transaction can get a pointer to unused memory

            // This method will always be called in the context of the current execution environment.
            memory_page& current_memory_page = *current_memory;
            current_memory_page.allocated_memory += msize;
            current_memory_page.stashed_free_memory = msize;
        }

        void restore_free_memory() noexcept
        {
            // We call this when control flow returns to a transaction, after an external call.
            // We assume that the external call has called memory::clean_up, so we know that the
            // subsequent memory in the memory page is zeroed out
            memory_page& current_memory_page = *current_memory;
            current_memory_page.allocated_memory -= current_memory_page.stashed_free_memory;
            current_memory_page.stashed_free_memory = 0;
        }

        void clean_up(size_t msize) noexcept
        {
            // Clean up after a transaction.
            // If the current memory page points has no allocated memory, and we have more than one
            // memory page, decrease # of memory pages by one
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
                // the current memory page is still the latest. We need to zero out the relevant amount of memory
                memory_page& current_memory_page = *current_memory;

                // zero memory between allocated memory and allocated memory + msize
                memset(current_memory_page.pointer + current_memory_page.allocated_memory, 0, msize * sizeof(uint8_t));
            }
        }
   }
}