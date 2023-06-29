
#include <cstddef>
#include <cstdint>

void rmd160_compress(uint32_t* h, const uint32_t* X) noexcept;

void ripemd160(uint8_t out[20], const uint8_t* ptr, size_t len);
