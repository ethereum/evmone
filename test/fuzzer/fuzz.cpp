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
        char buffer[sizeof(evmc::address) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, args...);
        const auto tmp = evmc::from_hex<evmc::address>(str);
        assert(tmp.has_value());
        addr = *tmp;
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

template <>
struct from<JSON, evmc::bytes32>
{
    template <auto Opts>
    static void op(evmc::bytes32& v, auto&&... args)
    {
        // Convert a hex string to bytes. It can happen that the input is truncated probably
        // because glaze can receive truncated file, and it will call this function while parsing.
        // In this case we should rather return a syntax error, but I don't know how to do it.
        char buffer[sizeof(evmc::bytes32) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, args...);
        const auto tmp = evmc::from_hex<evmc::bytes32>(str);
        assert(tmp.has_value());
        v = *tmp;
    }
};

template <>
struct to<JSON, evmc::bytes32>
{
    template <auto Opts>
    static void op(const evmc::bytes32& v, auto&&... args) noexcept
    {
        const auto str = evmc::hex(v);
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
    std::unordered_map<evmc::bytes32, evmc::bytes32> storage;
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

void mutate(std::integral auto& value, RNG&)
{
    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&value), sizeof(value), sizeof(value));
}

void mutate(evmc::address& value, RNG&)
{
    LLVMFuzzerMutate(value.bytes, sizeof(value), sizeof(value));
}

void mutate(evmc::bytes32& value, RNG&)
{
    LLVMFuzzerMutate(value.bytes, sizeof(value), sizeof(value));
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
    auto it = v.begin();
    if (index == v.size())
    {
        K new_key;
        mutate(new_key, rng);
        std::tie(it, std::ignore) = v.emplace(new_key, V{});
    }
    else
    {
        std::advance(it, index);
    }
    mutate(it->second, rng);
}

void mutate(std::string& value, RNG&)
{
    // We cannot treat strings as raw bytes because glaze don't properly escape control characters.
    // So let's use hex for now. Maybe this is not an issue in binary formats.

    auto bytes = evmc::from_hex(value);
    if (bytes.has_value())
    {
        const auto cur_size = bytes->size();
        const auto max_size = std::max(cur_size * 4 / 3, 4uz);
        bytes->resize(max_size);
        const auto new_size = LLVMFuzzerMutate(bytes->data(), cur_size, max_size);
        bytes->resize(new_size);
        value = evmc::hex(*bytes);
        return;
    }

    const auto cur_size = value.size();
    const auto max_size = std::max(cur_size * 4 / 3, 4uz);
    value.resize(max_size);
    const auto new_size =
        LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(value.data()), cur_size, max_size);
    value.resize(new_size);
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
        const auto it = test_.state.find(addr);
        if (it == test_.state.end())
            return std::nullopt;
        const auto& t = it->second;
        StateView::Account a{.nonce = t.nonce, .balance = t.balance};

        if (t.code.empty())
            a.code_hash = evmone::state::Account::EMPTY_CODE_HASH;

        return a;
    }

    evmc::bytes get_account_code(const evmc::address& addr) const noexcept override
    {
        const auto it = test_.state.find(addr);
        if (it == test_.state.end())
            return {};
        const auto& str_code = it->second.code;
        return *evmc::from_hex(str_code);
    }

    evmc::bytes32 get_storage(
        const evmc::address& addr, const evmc::bytes32& key) const noexcept override
    {
        const auto it = test_.state.find(addr);
        if (it == test_.state.end())
            return {};
        const auto& storage = it->second.storage;
        const auto it2 = storage.find(key);
        if (it2 == storage.end())
            return {};
        return it2->second;
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
        tx.to = it->first;
    }
    if (test.tx.sender < test.state.size())
    {
        auto it = test.state.begin();
        std::advance(it, test.tx.sender);
        tx.sender = it->first;
    }
    tx.data = *evmc::from_hex(test.tx.data);
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
        case NONCE_TOO_LOW:
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

    std::string out;
    if (const auto write_ec = glz::write<OPTS>(test, out))
    {
        std::cerr << "JSON write error: " << glz::format_error(write_ec, out) << '\n';
        __builtin_trap();
    }
    if (out.size() + 1 > max_size)
    {
        // std::cerr << "too big\n";
        return 0;
    }
    std::memcpy(data, out.c_str(), out.size() + 1);
    return out.size();
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
