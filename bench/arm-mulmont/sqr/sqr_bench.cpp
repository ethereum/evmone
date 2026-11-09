// sqr_bench test: the prototype squaring against the reference AMM, bit-exact.
// sqr_bench [reps] [n]: cycles per squaring in a chain, production mul_amm_asm(x, x) vs prototype.
#include "amm.hpp"
#include <evmone_precompiles/mulmod.hpp>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

using u64 = uint64_t;

namespace evmone::crypto
{
void proto_sqr_amm(u64* r, const u64* x, const u64* m, u64 m_inv, size_t n) noexcept;
void proto_sqr_part(u64* r, const u64* x, const u64* m, u64 m_inv, size_t n, int part) noexcept;
}  // namespace evmone::crypto

static u64 inv_neg(u64 m0)
{
    u64 inv = 1;
    for (int i = 0; i < 7; ++i)
        inv *= 2 - m0 * inv;
    return -inv;
}

static u64 word(std::mt19937_64& rng)
{
    switch (rng() % 6)
    {
    case 0:
        return ~u64{0};
    case 1:
        return 0;
    case 2:
        return ~u64{0} - (rng() % 4);
    default:
        return rng();
    }
}

static const size_t SIZES[] = {8, 12, 16, 20, 24, 32, 48, 64, 96, 128};

static int test()
{
    std::mt19937_64 rng{11};
    long fails = 0, checks = 0;
    for (const auto n : SIZES)
    {
        const int trials = n <= 16 ? 20000 : n <= 32 ? 5000 : 1000;
        std::vector<u64> m(n), x(n), r1(n), r2(n);
        for (int t = 0; t < trials; ++t)
        {
            for (auto& w : m)
                w = word(rng);
            m[0] |= 1;
            if (m[n - 1] == 0)
                m[n - 1] = 1 + rng() % 7;
            if (t % 5 == 0)
                m[n - 1] = ~u64{0};
            const auto mi = inv_neg(m[0]);
            for (auto& w : x)
                w = word(rng);
            if (t % 9 == 0)
                std::fill(x.begin(), x.end(), ~u64{0});
            amm::ref_amm(r1.data(), x.data(), x.data(), m.data(), mi, n);
            evmone::crypto::proto_sqr_amm(r2.data(), x.data(), m.data(), mi, n);
            ++checks;
            if (r1 != r2 && fails++ < 5)
                std::printf("FAIL n=%zu t=%d\n", n, t);
        }
    }
    std::printf("%s %ld of %ld\n", fails ? "FAILED" : "OK", fails, checks);
    return fails != 0;
}

/// CPU cycles where perf events work, otherwise unavailable (stop() returns 0).
struct Cycles
{
    int fd = -1;
    Cycles()
    {
#ifdef __linux__
        perf_event_attr a{};
        a.type = PERF_TYPE_HARDWARE;
        a.size = sizeof(a);
        a.config = PERF_COUNT_HW_CPU_CYCLES;
        a.disabled = 1;
        a.exclude_kernel = 1;
        a.exclude_hv = 1;
        fd = static_cast<int>(syscall(SYS_perf_event_open, &a, 0, -1, -1, 0));
#endif
    }
    void start() const
    {
#ifdef __linux__
        if (fd >= 0)
            ioctl(fd, PERF_EVENT_IOC_RESET, 0), ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
#endif
    }
    u64 stop() const
    {
        u64 v = 0;
#ifdef __linux__
        if (fd >= 0)
        {
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            if (read(fd, &v, sizeof(v)) != sizeof(v))
                v = 0;
        }
#endif
        return v;
    }
};

using Fn = void (*)(u64*, const u64*, const u64*, u64, size_t);

static void prod(u64* r, const u64* x, const u64* m, u64 mi, size_t n)
{
    evmone::crypto::mul_amm_asm(r, x, x, m, mi, n);
}
static void proto(u64* r, const u64* x, const u64* m, u64 mi, size_t n)
{
    evmone::crypto::proto_sqr_amm(r, x, m, mi, n);
}
template <int P>
static void part(u64* r, const u64* x, const u64* m, u64 mi, size_t n)
{
    evmone::crypto::proto_sqr_part(r, x, m, mi, n, P);
}

[[gnu::noinline]] static void chain(Fn f, u64* a, u64* b, const u64* m, u64 mi, size_t n, size_t iters)
{
    for (size_t i = 0; i < iters; ++i)
    {
        f(b, a, m, mi, n);
        f(a, b, m, mi, n);
    }
}

static double bench1(Fn f, size_t n, size_t reps)
{
    std::mt19937_64 rng{n};
    alignas(64) static u64 m[128], a[128], b[128];
    for (size_t i = 0; i < n; ++i)
        m[i] = rng(), a[i] = rng() >> 1;
    m[0] |= 1;
    m[n - 1] |= u64{1} << 63;
    const auto mi = inv_neg(m[0]);
    const size_t iters = std::max<size_t>(40000 / (n * n), 2) * 10;
    static Cycles cyc;
    double best = 1e30;
    chain(f, a, b, m, mi, n, iters);
    for (size_t rep = 0; rep < reps; ++rep)
    {
        const auto t0 = std::chrono::steady_clock::now();
        cyc.start();
        chain(f, a, b, m, mi, n, iters);
        const auto c = cyc.stop();
        const auto ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count();
        best = std::min(best, c != 0 ? double(c) : ns);
    }
    return best / double(2 * iters);
}

int main(int argc, char** argv)
{
    if (argc > 1 && std::strcmp(argv[1], "test") == 0)
        return test();
    const size_t reps = argc > 1 ? std::strtoul(argv[1], nullptr, 10) : 15;
    const size_t only = argc > 2 ? std::strtoul(argv[2], nullptr, 10) : 0;
    const bool parts = std::getenv("PARTS") != nullptr;
    std::printf("%s per squaring\n", Cycles{}.fd >= 0 ? "cycles" : "ns");
    std::printf("%5s %9s %9s %7s", "n", "mul", "sqr", "sqr/mul");
    if (parts)
        std::printf(" %9s %9s %9s %9s", "zero", "+tri", "+dbl", "+redc");
    std::printf("\n");
    for (const auto n : SIZES)
    {
        if (only != 0 && n != only)
            continue;
        const auto c0 = bench1(prod, n, reps);
        const auto c1 = bench1(proto, n, reps);
        std::printf("%5zu %9.1f %9.1f %7.3f", n, c0, c1, c1 / c0);
        if (parts)
            std::printf(" %9.1f %9.1f %9.1f %9.1f", bench1(part<0>, n, reps), bench1(part<1>, n, reps),
                bench1(part<2>, n, reps), bench1(part<3>, n, reps));
        std::printf("\n");
    }
}
