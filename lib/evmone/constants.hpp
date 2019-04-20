#pragma once

#include <stddef.h>

namespace evmone
{
    // The minimum size of a memory page
    static const size_t BASE_MEMORY_POOL_SIZE = 0x4000000; // 64 MB
    // The number of elements in our opcode jump table
    static const int JUMP_TABLE_SIZE = 0x201;
    // The first index inside our opcode jump table that contains 'no_check' labels
    static const int JUMP_TABLE_CHECK_BOUNDARY = 0x100;
    // An index in our opcode table that contains &&op_undefined_dest
    static const int UNDEFINED_INDEX = 0x0c;
    // The index in our opcode table that contains &&op_staticviolation_dest
    static const int STATIC_VIOLATION_INDEX = 0x200;
}   // namespace evmone