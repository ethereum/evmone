#include <evmc/evmc.hpp>
#include <glaze/glaze.hpp>
#include <boost/ut.hpp>

namespace glz::detail
{
template <>
struct from<JSON, evmc::address>
{
    template <auto Opts>
    static void op(evmc::address& addr, auto&&... args)
    {
        char buffer[40];
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, args...);
        addr = evmc::from_hex<evmc::address>(str).value();
    }
};

template <>
struct to<JSON, evmc::address>
{
    template <auto Opts>
    static void op(const evmc::address& addr, auto&&... args) noexcept
    {
        const auto str = evmc::hex(addr);
        write<JSON>::op<Opts>(str, args...);
    }
};
}  // namespace glz::detail

namespace fzz
{
struct Account
{
    uint32_t nonce = 0;
    uint32_t balance = 0;
    std::string code;
};

struct Block
{
    uint32_t gas_limit = 0;
};

struct Tx
{
    uint8_t to = 0;
    uint8_t sender = 0;
    uint32_t gas_limit = 0;
    std::string data;
};

struct Test
{
    std::unordered_map<evmc::address, Account> state;
    Block block;
    Tx tx;
};
}  // namespace fzz

int main()
{
    using namespace boost::ut;

    "syntax_error_1"_test = [] {
        static constexpr glz::opts OPTS{.null_terminated = false};
        std::string buf =
            R"({"state":{"\\"0000000000000000000000000000000000000000\\"":{"nonce":0,"balance":0,"code":""}},"block":{"gas_limit":4},"tx":{"to":1,"sender":1,"gas_limit":524288,"data":"_"}})";

        fzz::Test t;
        const auto ec = glz::read<OPTS>(t, buf);
        const auto descriptive_error = glz::format_error(ec, buf);
        std::cerr << "JSON read error: " << descriptive_error << '\n';
        std::cerr << buf << '\n';
        expect(!ec);
    };

    return 0;
}
