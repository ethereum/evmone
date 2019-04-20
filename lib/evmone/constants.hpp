#pragma once

#include <stddef.h>

namespace evmone
{
    static const size_t BASE_MEMORY_POOL_SIZE = 0x4000000; // 64 MB
    static const int JUMP_TABLE_SIZE = 0x201;
    static const int JUMP_TABLE_CHECK_BOUNDARY = 0x100;
    static const int UNDEFINED_INDEX = 0x0c;
    static const int STATIC_VIOLATION_INDEX = 0x200;
}   // namespace evmone