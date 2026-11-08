// bench_proto test: the prototype 4-word procs against the reference AMM, bit-exact.
// bench_proto [reps]: ns (and cycles where perf events work) per call: latency (a chain of
// squarings or multiplications) and throughput (4 independent chains).
#include "amm.hpp"
#include <evmone_precompiles/mulmod.hpp>
#include <array>
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
EVMONE_PRESERVE_NONE void proto_sqr4(u64* r, const u64* x, const u64* m, u64 m_inv) noexcept;
EVMONE_PRESERVE_NONE void proto_sqr_chain4(
    u64* r, const u64* x, size_t k, const u64* m, u64 m_inv) noexcept;
EVMONE_PRESERVE_NONE void proto_ahead4(
    u64* r, const u64* x, const u64* y, const u64* m, u64 m_inv) noexcept;
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

struct Prod
{
    static constexpr const char* name = "prod";
    static void f(u64* r, const u64* x, const u64* y, const u64* m, u64 mi) noexcept
    {
        evmone::crypto::mul_amm_asm(r, x, y, m, mi, 4);
    }
};
struct Ahead
{
    static constexpr const char* name = "ahead";
    static void f(u64* r, const u64* x, const u64* y, const u64* m, u64 mi) noexcept
    {
        evmone::crypto::proto_ahead4(r, x, y, m, mi);
    }
};
struct Sqr
{
    static constexpr const char* name = "sqr";
    static void f(u64* r, const u64* x, const u64*, const u64* m, u64 mi) noexcept
    {
        evmone::crypto::proto_sqr4(r, x, m, mi);
    }
};

static int test(long trials)
{
    std::mt19937_64 rng{7};
    long fails = 0;
    constexpr size_t n = 4;
    std::vector<u64> m(n), x(n), y(n), r1(n), r2(n), r3(n);
    for (long t = 0; t < trials; ++t)
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
        for (auto& w : y)
            w = word(rng);
        amm::ref_amm(r1.data(), x.data(), x.data(), m.data(), mi, n);
        Sqr::f(r2.data(), x.data(), x.data(), m.data(), mi);
        if (r1 != r2 && fails++ < 3)
            std::printf("FAIL sqr\n");
        amm::ref_amm(r1.data(), x.data(), y.data(), m.data(), mi, n);
        Ahead::f(r2.data(), x.data(), y.data(), m.data(), mi);
        Prod::f(r3.data(), x.data(), y.data(), m.data(), mi);
        if (r1 != r2 && fails++ < 3)
            std::printf("FAIL ahead\n");
        if (r1 != r3 && fails++ < 3)
            std::printf("FAIL prod\n");
    }
    for (long t = 0; t < trials / 10; ++t)
    {
        for (auto& w : m)
            w = word(rng);
        m[0] |= 1;
        if (m[n - 1] == 0)
            m[n - 1] = 1;
        const auto mi = inv_neg(m[0]);
        for (auto& w : x)
            w = word(rng);
        const size_t k = 1 + rng() % 9;
        std::vector<u64> a = x, b(n);
        for (size_t i = 0; i < k; ++i)
        {
            amm::ref_amm(b.data(), a.data(), a.data(), m.data(), mi, n);
            a = b;
        }
        evmone::crypto::proto_sqr_chain4(r2.data(), x.data(), k, m.data(), mi);
        if (a != r2 && fails++ < 3)
            std::printf("FAIL chain\n");
    }
    std::printf("%s %ld of %ld\n", fails ? "FAILED" : "OK", fails, 3 * trials + trials / 10);
    return fails != 0;
}

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

template <typename K, int L>
[[gnu::noinline]] void chains(u64 (*a)[4], u64 (*b)[4], const u64* m, u64 mi, size_t iters)
{
    for (size_t i = 0; i < iters; ++i)
    {
        for (int l = 0; l < L; ++l)
            K::f(b[l], a[l], a[l], m, mi);
        for (int l = 0; l < L; ++l)
            K::f(a[l], b[l], b[l], m, mi);
    }
}

template <typename K, int L>
static void bench1(size_t reps)
{
    std::mt19937_64 rng{4};
    alignas(64) u64 m[4];
    for (auto& w : m)
        w = rng();
    m[0] |= 1;
    m[3] |= u64{1} << 63;
    alignas(64) u64 a[L][4];
    alignas(64) u64 b[L][4];
    for (auto& v : a)
        for (auto& w : v)
            w = rng() >> 1;
    const auto mi = inv_neg(m[0]);
    const size_t iters = 20000;
    static Cycles cyc;
    double best_ns = 1e30;
    u64 best_c = ~u64{0};
    chains<K, L>(a, b, m, mi, iters);
    for (size_t rep = 0; rep < reps; ++rep)
    {
        const auto t0 = std::chrono::steady_clock::now();
        cyc.start();
        chains<K, L>(a, b, m, mi, iters);
        const auto c = cyc.stop();
        const auto ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count();
        if (ns < best_ns)
            best_ns = ns;
        if (c != 0 && c < best_c)
            best_c = c;
    }
    const auto calls = double(2 * iters * L);
    std::printf("%-6s %s ns/call %6.2f", K::name, L == 1 ? "lat" : "thr", best_ns / calls);
    if (best_c != ~u64{0})
        std::printf("  cyc/call %6.1f", double(best_c) / calls);
    std::printf("\n");
}

static void bench_chain(size_t reps)
{
    std::mt19937_64 rng{4};
    alignas(64) u64 m[4];
    alignas(64) u64 a[4];
    alignas(64) u64 b[4];
    for (auto& w : m)
        w = rng();
    m[0] |= 1;
    m[3] |= u64{1} << 63;
    for (auto& w : a)
        w = rng() >> 1;
    const auto mi = inv_neg(m[0]);
    const size_t k = 40000;
    static Cycles cyc;
    double best_ns = 1e30;
    u64 best_c = ~u64{0};
    evmone::crypto::proto_sqr_chain4(b, a, k, m, mi);
    for (size_t rep = 0; rep < reps; ++rep)
    {
        const auto t0 = std::chrono::steady_clock::now();
        cyc.start();
        evmone::crypto::proto_sqr_chain4(b, a, k, m, mi);
        const auto c = cyc.stop();
        const auto ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count();
        if (ns < best_ns)
            best_ns = ns;
        if (c != 0 && c < best_c)
            best_c = c;
    }
    std::printf("%-6s %s ns/call %6.2f", "chain", "lat", best_ns / double(k));
    if (best_c != ~u64{0})
        std::printf("  cyc/call %6.1f", double(best_c) / double(k));
    std::printf("\n");
}

int main(int argc, char** argv)
{
    if (argc > 1 && std::strcmp(argv[1], "test") == 0)
        return test(argc > 2 ? std::atol(argv[2]) : 1000000);
    const size_t reps = argc > 1 ? std::strtoul(argv[1], nullptr, 10) : 30;
    for (int round = 0; round < 3; ++round)
    {
        bench1<Prod, 1>(reps);
        bench1<Ahead, 1>(reps);
        bench1<Sqr, 1>(reps);
        bench_chain(reps);
        bench1<Prod, 4>(reps);
        bench1<Ahead, 4>(reps);
        bench1<Sqr, 4>(reps);
    }
}
