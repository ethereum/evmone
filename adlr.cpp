#include <errno.h>
#include <sys/personality.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <type_traits>

template <typename T>
std::make_unsigned_t<T> get_as_unsigned(T v) {
    using UnsignedT = std::make_unsigned_t<T>;
    return static_cast<UnsignedT>(v);
}

void MaybeReenterWithoutASLR(int /*argc*/, char** argv)
{
    // On e.g. Hexagon simulator, argv may be NULL.
    if (!argv) return;

    const auto curr_personality = personality(0xffffffff);

    // We should never fail to read-only query the current personality,
    // but let's be cautious.
    if (curr_personality == -1)
    {
        std::puts("reading personality failed");
        return;
    }

    // If ASLR is already disabled, we have nothing more to do.
    if (get_as_unsigned(curr_personality) & ADDR_NO_RANDOMIZE)
    {
        std::puts("ADLR disabled");
        return;
    }

    // Try to change the personality to disable ASLR.
    const auto proposed_personality =
        get_as_unsigned(curr_personality) | ADDR_NO_RANDOMIZE;
    const auto prev_personality = personality(proposed_personality);

    // Have we failed to change the personality? That may happen.
    if (prev_personality == -1)
    {
        std::puts("changing personality failed");
        std::puts(std::strerror(errno));
        return;
    }

    // // If ASLR is already disabled, we have nothing more to do.
    // if (get_as_unsigned(prev_personality) & ADDR_NO_RANDOMIZE)
    // {
    //     std::puts("ADLR disabled 2");
    //     return;
    // }

    // Check if flag applied.
    const auto new_personality = personality(0xffffffff);
    if ((get_as_unsigned(new_personality) & ADDR_NO_RANDOMIZE) == 0)
    {
        std::puts("setting ADLR failed");
        return;
    }

    std::puts("reexecuting");
    execv(argv[0], argv);
    // The exec() functions return only if an error has occurred,
    // in which case we want to just continue as-is.
    std::puts("execv has returned");
}

int main(int argc, char** argv) {
    MaybeReenterWithoutASLR(argc, argv);
    return 0;
}
