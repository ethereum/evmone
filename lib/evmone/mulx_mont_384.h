// Provided by BLST team (https://gist.github.com/poemm/7acc919be1b120594969a0ac3bfdcb04)

#pragma once

#include <cstdint>

extern "C" void mulx_mont_384(
    uint64_t* out, const uint64_t* x, const uint64_t* y, const uint64_t* m, uint64_t inv) noexcept;
