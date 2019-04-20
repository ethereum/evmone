#include <gtest/gtest.h>

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
    size_t gas = 8000000; // 8 million gas
    uint8_t* first;
    size_t max_size = 0xffff;
    first = evmone::memory::get_tx_memory_ptr(gas);
    evmone::memory::memory_page current_memory_page = evmone::memory::get_current_memory_page();
    first[max_size - 1] = 0xff;
    EXPECT_EQ(current_memory_page.allocated_memory, 0);
    EXPECT_EQ(evmone::memory::get_num_memory_pages(), 1);
    EXPECT_EQ(first[max_size - 1], 0xff);
}

// TODO:
// validate clean_up works if num pages = 1
// validate clean_up works if num pages > 1
// validate that a previous txn's memory is genuinely cleaned up
// validate that a new page is created iff the previous page cannot accomodate