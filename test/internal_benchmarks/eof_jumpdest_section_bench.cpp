
#include <benchmark/benchmark.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>

template <typename T>
inline std::pair<T, const uint8_t*> leb128u_decode_safe(const uint8_t* pos, const uint8_t* end)
{
    static_assert(!std::numeric_limits<T>::is_signed);

    T result = 0;
    int result_shift = 0;

    for (; result_shift < std::numeric_limits<T>::digits; ++pos, result_shift += 7)
    {
        if (pos == end)
            throw "unexpected EOF";

        result |= static_cast<T>((static_cast<T>(*pos) & 0x7F) << result_shift);
        if ((*pos & 0x80) == 0)
        {
            if (*pos != (result >> result_shift))
                throw "invalid LEB128 encoding: unused bits set";

            return {result, pos + 1};
        }
    }

    throw "invalid LEB128 encoding: too many bytes";
}

template <typename T>
inline std::pair<T, const uint8_t*> leb128u_decode_fast(
    const uint8_t* pos, [[maybe_unused]] const uint8_t* end) noexcept
{
    static_assert(!std::numeric_limits<T>::is_signed);

    T result = 0;
    int result_shift = 0;

    for (; result_shift < std::numeric_limits<T>::digits; ++pos, result_shift += 7)
    {
        result |= static_cast<T>((static_cast<T>(*pos) & 0x7F) << result_shift);
        if (__builtin_expect((*pos & 0x80) == 0, true))
            break;
    }

    return {result, pos + 1};
}

template <std::pair<uint16_t, const uint8_t*> DecodeFn(const uint8_t*, const uint8_t*)>
static std::vector<bool> load_jumpdests(const uint8_t* pos, const uint8_t* end, size_t code_size)
{
    std::vector<bool> m;
    m.resize(code_size);
    size_t partial_sum = 0;
    while (pos < end)
    {
        auto [v, new_pos] = DecodeFn(pos, end);
        partial_sum += v;
        m[partial_sum] = true;
        pos = new_pos;
    }
    return m;
}

template <std::vector<bool> Fn(const uint8_t*, const uint8_t*, size_t)>
static void load_jumpdests(benchmark::State& state)
{
    // Create jumpdests section marking all positions as valid JUMPDESTs.
    static constexpr size_t size = 0xffff;
    auto section = std::vector<uint8_t>(size, uint8_t{1});
    section[0] = 0;
    const auto* const begin = section.data();
    const auto* const end = begin + size;

    // Check result
    if (const auto r = Fn(begin, end, size); std::count(r.begin(), r.end(), true) != size)
        state.SkipWithError("incorrect jumpdest map");

    for (auto _ : state)
    {
        const auto r = Fn(begin, end, size);
        benchmark::DoNotOptimize(r);
    }
}

static constexpr auto load_jumpdests_safe = load_jumpdests<leb128u_decode_safe<uint16_t>>;
static constexpr auto load_jumpdests_fast = load_jumpdests<leb128u_decode_fast<uint16_t>>;
BENCHMARK_TEMPLATE(load_jumpdests, load_jumpdests_safe)->Unit(benchmark::kMicrosecond);
BENCHMARK_TEMPLATE(load_jumpdests, load_jumpdests_fast)->Unit(benchmark::kMicrosecond);


static void memcpy(benchmark::State& state)
{
    // Create jumpdests section marking all positions as valid JUMPDESTs.
    size_t size = 0xffff;
    benchmark::DoNotOptimize(size);
    auto section = std::vector<uint8_t>(size, uint8_t{1});
    auto sink = std::vector<uint8_t>(size);

    for (auto _ : state)
    {
        benchmark::ClobberMemory();
        std::memcpy(sink.data(), section.data(), size);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(memcpy)->Unit(benchmark::kMicrosecond);
