#include "../state/state.hpp"
#include "evmone/evmone.h"

#include <glaze/glaze.hpp>

#include <iostream>
#include <random>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size) noexcept;

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
using RNG = std::minstd_rand;

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
    std::unordered_map<std::string, Account> state;
    Block block;
    Tx tx;
};

void mutate(std::integral auto& value, RNG&)
{
    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&value), sizeof(value), sizeof(value));
}

void mutate(evmc::address& value, RNG&)
{
    LLVMFuzzerMutate(value.bytes, sizeof(value), sizeof(value));
}

void mutate(std::string& value, RNG&)
{
    const auto cur_size = value.size();
    const auto max_size = std::max(cur_size * 4 / 3, 1uz);
    value.resize(max_size);
    const auto new_size =
        LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(value.data()), cur_size, max_size);
    value.resize(new_size);
}

template <typename T>
void mutate(std::vector<T>& v, RNG& rng)
{
    const auto index = rng() % (v.size() + 1);
    if (index == v.size())
        v.emplace_back();
    mutate(v[index], rng);
}

template <typename K, typename V>
void mutate(std::unordered_map<K, V>& v, RNG& rng)
{
    const auto index = rng() % (v.size() + 1);
    if (index == v.size())
    {
        K new_addr;
        mutate(new_addr, rng);
        v.emplace(new_addr, V{});
    }
    else
    {
        auto it = v.begin();
        std::advance(it, index);
        mutate(it->second, rng);
    }
}

template <typename T>
void mutate(T& value, RNG& rng)
{
    using R = glz::reflect<T>;
    const auto index = rng() % R::size;

    size_t c = 0;
    glz::for_each_field(value, [&](auto& field) {
        if (c == index)
        {
            mutate(field, rng);
        }
        ++c;
    });
}

class StateView : public evmone::state::StateView
{
    const Test& test_;

public:
    StateView(const Test& test) : test_{test} {}

    std::optional<Account> get_account(const evmc::address& addr) const noexcept override
    {
        const auto it = test_.state.find(hex(addr));
        if (it == test_.state.end())
            return std::nullopt;
        const auto& t = it->second;
        StateView::Account a{.nonce = t.nonce, .balance = t.balance};
        return a;
    }

    evmc::bytes get_account_code(const evmc::address& addr) const noexcept override
    {
        const auto it = test_.state.find(hex(addr));
        if (it == test_.state.end())
            return {};
        const auto& str_code = it->second.code;
        return evmc::bytes(str_code.begin(), str_code.end());
    }

    evmc::bytes32 get_storage(
        const evmc::address& addr, const evmc::bytes32& key) const noexcept override
    {
        (void)addr;
        (void)key;
        return {};
    }
};

class BlockHashes : public evmone::state::BlockHashes
{
public:
    evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override
    {
        (void)block_number;
        return {};
    }
};


static auto vm = evmc::VM{evmc_create_evmone()};


void execute(const Test& test)
{
    const StateView state_view{test};

    evmone::state::BlockInfo block;
    block.gas_limit = test.block.gas_limit;

    evmone::state::Transaction tx;
    if (test.tx.to < test.state.size())
    {
        auto it = test.state.begin();
        std::advance(it, test.tx.to);
        evmc::address a;
        std::memcpy(a.bytes, it->first.data(), std::min(sizeof(a), it->first.size()));
        tx.to = a;
    }
    if (test.tx.sender < test.state.size())
    {
        auto it = test.state.begin();
        std::advance(it, test.tx.sender);
        evmc::address a;
        std::memcpy(a.bytes, it->first.data(), std::min(sizeof(a), it->first.size()));
        tx.sender = a;
    }
    tx.data = evmone::bytes{test.tx.data.begin(), test.tx.data.end()};
    tx.gas_limit = test.tx.gas_limit;

    const auto res = evmone::state::validate_transaction(
        state_view, block, tx, EVMC_LATEST_STABLE_REVISION, 1'000'000, 0);

    if (std::holds_alternative<std::error_code>(res))
    {
        const auto ec = std::get<std::error_code>(res);
        switch (ec.value())
        {
            using namespace evmone::state;
        case INTRINSIC_GAS_TOO_LOW:
        case SENDER_NOT_EOA:
        case GAS_LIMIT_REACHED:
            break;
        case INSUFFICIENT_FUNDS:
            assert(false && "INSUFFICIENT_FUNDS");
            break;
        default:
            std::cerr << "new error: " << ec.message() << '\n';
            break;
        }
        return;
    }

    const auto execution_gas_limit = std::get<int64_t>(res);
    BlockHashes block_hashes;
    evmone::state::transition(
        state_view, block, block_hashes, tx, EVMC_LATEST_STABLE_REVISION, vm, execution_gas_limit);
}

}  // namespace fzz

static constexpr glz::opts OPTS{.null_terminated = false};


extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, uint32_t seed)
{
    fzz::RNG rng{seed};
    const std::string_view buffer{reinterpret_cast<const char*>(data), size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (!ec)
    {
        fzz::mutate(test, rng);
    }
    else
    {
        const auto descriptive_error = glz::format_error(ec, buffer);
        std::cerr << "JSON read error: " << descriptive_error << '\n';
        std::cerr << buffer << '\n';
        __builtin_trap();
    }

    auto e = glz::write_json(test);
    if (e.has_value())
    {
        const auto& s = e.value();
        if (s.size() + 1 > max_size)
        {
            // std::cerr << "too big\n";
            return 0;
        }
        std::memcpy(data, s.c_str(), s.size() + 1);
        return s.size();
    }

    const auto descriptive_error = glz::format_error(e.error(), buffer);
    std::cerr << "JSON write error: " << descriptive_error << '\n';
    __builtin_trap();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const std::string_view buffer{reinterpret_cast<const char*>(data), data_size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (ec)
        return -1;

    fzz::execute(test);

    return 0;
}
