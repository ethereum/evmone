#pragma once
#include <cstddef>
#include <cstdint>

#if defined(AMM_PN) && defined(__has_attribute)
#if __has_attribute(preserve_none)
#define AMM_PROC __attribute__((preserve_none))
#endif
#endif
#ifndef AMM_PROC
#define AMM_PROC
#endif

namespace amm
{
AMM_PROC void amm(uint64_t* r, const uint64_t* x, const uint64_t* y, const uint64_t* m,
    uint64_t m_inv, size_t n) noexcept;
void ref_amm(uint64_t* r, const uint64_t* x, const uint64_t* y, const uint64_t* m, uint64_t m_inv,
    size_t n) noexcept;
}  // namespace amm
