#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <bit>
#include <cstdio>

struct alignas(256) U256 {
    uint64_t words[4];
};

static constexpr size_t NumElems = 1024;
static constexpr size_t StackSize = NumElems * sizeof(U256);

struct Stack {
    U256 *elems;

    Stack() {
        elems = static_cast<U256 *>(std::aligned_alloc(StackSize, StackSize));
        assert(elems != nullptr);
    }

    ~Stack() {
        std::free(elems);
    }

    Stack(const Stack &) = delete;

    Stack &operator=(const Stack &) = delete;
};

static bool check_in_bounds(uintptr_t top, std::ptrdiff_t offset) {
    static constexpr auto magic_bit_mask = StackSize;
    static_assert(std::popcount(magic_bit_mask) == 1);

    auto p = top + uintptr_t(offset * std::ptrdiff_t(sizeof(U256)));
    return (top & magic_bit_mask) == (p & magic_bit_mask);
}

static size_t get_size(uintptr_t top) {
    auto align_mask = (StackSize - 1);
    auto bottom = top & ~align_mask;
    return (top - bottom) / sizeof(U256);
}


int main() {

    uintptr_t bottom = StackSize;

    std::printf("bottom: %lx\n", bottom);
    std::printf("magic bit: %lx\n", (bottom & StackSize) >> 18);

    for (size_t s = 0; s < NumElems; ++s)
    {
        auto top = bottom + s * sizeof(U256);
        assert(check_in_bounds(top, 0));
        assert(get_size(top) == s);
    }

    return 0;
}
