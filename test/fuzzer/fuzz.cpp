#include <glaze/glaze.hpp>
#include "../state/state.hpp"

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    std::string buffer{reinterpret_cast<const char*>(data), data_size};

    fzz::Test test;
    const auto ec = glz::read_json(test, buffer);
    if (ec)
        return -1;

    evmone::state::Transaction tx;
    tx.data = evmone::bytes{test.tx.data.begin(), test.tx.data.end()};

    evmone::state::validate_transaction()

    return 0;
}
