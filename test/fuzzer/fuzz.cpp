#include "../state/state.hpp"
#include <glaze/glaze.hpp>

namespace fzz
{
struct Account
{
    int nonce = 0;
    int balance = 0;
    std::string code;
};

struct Tx
{
    std::string data;
};

struct Test
{
    std::vector<Account> state;
    Tx tx;
};
}  // namespace fzz

static constexpr glz::opts OPTS{.null_terminated = false};


extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    (void)seed;
    const std::string_view buffer{reinterpret_cast<const char*>(data), size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (!ec)
    {
        // mutate.
    }

    auto e = glz::write_json(test);
    if (e.has_value())
    {
        auto s = e.value();
        if (s.size() > max_size)
            return 0;
        std::memcpy(data, s.data(), s.size());
        return s.size();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const std::string_view buffer{reinterpret_cast<const char*>(data), data_size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (ec)
        return -1;

    evmone::state::Transaction tx;
    tx.data = evmone::bytes{test.tx.data.begin(), test.tx.data.end()};

    // evmone::state::validate_transaction()

    return 0;
}
