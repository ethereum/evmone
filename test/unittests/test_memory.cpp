#include <gtest/gtest.h>

#include <evmone/constants.hpp>
#include <evmone/memory.hpp>

#include <iostream>


TEST(memory, initialized)
{
    evmone::memory::memory_page current_memory_page = evmone::memory::get_current_memory_page();
    EXPECT_EQ(current_memory_page.allocated_memory, 0);
    EXPECT_EQ(evmone::memory::get_num_memory_pages(), 1);
}

TEST(memory, validate_allocation)
{
    int64_t gas = 8000000; // 8 million gas
    uint8_t* first;
    int64_t max_size = evmone::memory::map_gas_to_memory_ceiling(gas);
    first = evmone::memory::get_tx_memory_ptr(gas);
    evmone::memory::memory_page current_memory_page = evmone::memory::get_current_memory_page();
    first[max_size] = 0xff;
    EXPECT_EQ(current_memory_page.allocated_memory, 0);
    EXPECT_EQ(evmone::memory::get_num_memory_pages(), 1);
    EXPECT_EQ(first[max_size], 0xff);
    evmone::memory::clean_up(max_size);
}

TEST(memory, multiple_pages)
{
    int64_t gas = 100000000000; // 100 BILLION gas!
    size_t max_size = evmone::memory::map_gas_to_memory_ceiling(gas);
    evmone::memory::get_tx_memory_ptr(gas);
    EXPECT_EQ(max_size > evmone::BASE_MEMORY_POOL_SIZE, true);
    EXPECT_EQ(evmone::memory::get_num_memory_pages(), 2);
    evmone::memory::clean_up(max_size);
    EXPECT_EQ(evmone::memory::get_num_memory_pages(), 1);
}

TEST(memory, stash_and_clean_up)
{
    int64_t gas = 10000000;
    // get # bytes we can access with 10 million gas. This should fall well within BASE_MEMORY_POOL_SIZE
    size_t max_size = evmone::memory::map_gas_to_memory_ceiling(gas);
    // get a pointer to a reserved block of memory, for 10 million gas
    uint8_t* first = evmone::memory::get_tx_memory_ptr(gas);
    // write 0xaa into the top byte
    first[max_size] = 0xaa;
    // stash (max_size + 1), in preparation for getting a pointer to a fresh block of memory
    evmone::memory::stash_free_memory(max_size + 1);

    // get a pointer to a new reserved block of memory, for 10 million gas
    uint8_t* second = evmone::memory::get_tx_memory_ptr(gas);
    // write 0xbb into the 0th byte
    second[0] = 0xbb;

    // the address of the last byte of the 1st block, should be adjacent to the first byte of the 2nd block
    EXPECT_EQ(&first[max_size + 1], &second[0]);
    // memory should be where we left it!
    EXPECT_EQ(first[max_size], 0xaa);
    EXPECT_EQ(second[0], 0xbb);

    // get metrics for the current page
    evmone::memory::memory_page current_page = evmone::memory::get_current_memory_page();

    // we should have (max_size + 1) allocated memory
    EXPECT_EQ(current_page.allocated_memory, max_size + 1);
    // we should have (max_size + 1) stashed memory
    EXPECT_EQ(current_page.stashed_free_memory, max_size + 1);

    // clean up the byte we wrote, in preparation for releasing the 2nd block.
    evmone::memory::clean_up(1);
    // free up the 2nd block of memory
    evmone::memory::restore_free_memory();

    // refresh our metrics for the current page
    current_page = evmone::memory::get_current_memory_page();

    // we should have no allocated memory
    EXPECT_EQ(current_page.allocated_memory, 0x0);

    // max_memory should be unchanged
    EXPECT_EQ(current_page.max_memory, evmone::BASE_MEMORY_POOL_SIZE);

    // we should no longer have any stashed free memory
    EXPECT_EQ(current_page.stashed_free_memory, 0x0);

    // and that byte we wrote should be 0 (but still point to allocated memory)
    EXPECT_EQ(second[0], 0x00);
}
