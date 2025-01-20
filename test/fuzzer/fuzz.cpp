#include "../state/state.hpp"
#include "evmone/evmone.h"

#include <glaze/glaze.hpp>

#include <iostream>
#include <random>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size) noexcept;

using namespace evmc::literals;

static constexpr auto SENDER = 0xe100713FC15400D1e94096a545879E7c6407001e_address;

namespace glz::detail
{
template <>
struct from<JSON, evmc::address>
{
    template <auto Opts, is_context Ctx>
    static void op(evmc::address& v, Ctx&& ctx, auto&&... args)
    {
        char buffer[sizeof(evmc::address) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, ctx, args...);
        const auto tmp = evmc::from_hex<evmc::address>(str);

        // This can be invalid hex string (e.g. truncated by -max_len).
        if (tmp.has_value())
            v = *tmp;
        else
            ctx.error = error_code::elements_not_convertible_to_design;
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
    template <auto Opts, is_context Ctx>
    static void op(evmc::bytes32& v, Ctx&& ctx, auto&&... args)
    {
        // Convert a hex string to bytes.
        char buffer[sizeof(evmc::bytes32) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, ctx, args...);
        const auto tmp = evmc::from_hex<evmc::bytes32>(str);

        // This can be invalid hex string (e.g. truncated by -max_len).
        if (tmp.has_value())
            v = *tmp;
        else
            ctx.error = error_code::elements_not_convertible_to_design;
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
    uint32_t number = 0;
    uint32_t timestamp = 0;
    uint32_t gas_limit = 0;
    evmc::address coinbase;
    evmc::bytes32 prev_randao;
    uint64_t base_fee = 0;
    uint64_t blob_base_fee = 0;
};

struct Tx
{
    evmone::state::Transaction::Type type = evmone::state::Transaction::Type::legacy;
    uint8_t to = 0;

    // We use fixed sender to make sure it is EOA and has private key.
    // uint8_t sender = 0;

    uint32_t gas_limit = 0;
    std::string data;
    uint64_t max_gas_price = 0;
    uint64_t max_priority_gas_price = 0;
    uint64_t max_blob_gas_price = 0;
    evmc::bytes32 value;
    uint64_t chain_id;
    uint64_t nonce;
    std::vector<evmc::bytes32> blob_hashes;
    // TODO: Add access list.
};

struct Test
{
    std::unordered_map<evmc::address, Account> state;
    Block block;
    Tx tx;
};

void mutate(evmone::state::Transaction::Type& type, RNG&)
{
    type = static_cast<evmone::state::Transaction::Type>((std::to_underlying(type) + 1) % 4);
}

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
    block.number = test.block.number;
    block.timestamp = test.block.timestamp;
    block.gas_limit = test.block.gas_limit;
    block.coinbase = test.block.coinbase;
    block.prev_randao = test.block.prev_randao;
    block.base_fee = test.block.base_fee;
    block.blob_base_fee = test.block.blob_base_fee;

    evmone::state::Transaction tx;
    tx.type = test.tx.type;
    if (test.tx.to < test.state.size())
    {
        auto it = test.state.begin();
        std::advance(it, test.tx.to);
        tx.to = it->first;
    }
    tx.sender = SENDER;
    tx.data = *evmc::from_hex(test.tx.data);
    tx.gas_limit = test.tx.gas_limit;
    tx.max_gas_price = test.tx.max_gas_price;
    tx.max_priority_gas_price = test.tx.max_priority_gas_price;
    tx.max_blob_gas_price = test.tx.max_blob_gas_price;
    tx.value = intx::be::load<intx::uint256>(test.tx.value);
    tx.chain_id = test.tx.chain_id;
    tx.nonce = test.tx.nonce;
    tx.blob_hashes = test.tx.blob_hashes;

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
        case NONCE_TOO_HIGH:
        case FEE_CAP_LESS_THEN_BLOCKS:
        case INSUFFICIENT_FUNDS:
        case CREATE_BLOB_TX:
        case EMPTY_BLOB_HASHES_LIST:
        case INVALID_BLOB_HASH_VERSION:
            break;
        default:
            std::cerr << "new error: " << ec.message() << '\n';
            break;
        }
        return;
    }

    const auto tx_props = std::get<evmone::state::TransactionProperties>(res);
    BlockHashes block_hashes;
    evmone::state::transition(
        state_view, block, block_hashes, tx, EVMC_LATEST_STABLE_REVISION, vm, tx_props);
}

}  // namespace fzz

static constexpr glz::opts OPTS{
    .null_terminated = false,
    .error_on_unknown_keys = false,

    // Require the input to be minified. This is supposed to make the reading faster, but looks like
    // it makes it slower. Investigate later.
    .minified = true,
};


extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, uint32_t seed)
{
    fzz::RNG rng{seed};
    const std::string_view buffer{reinterpret_cast<const char*>(data), size};

    fzz::Test test;
    if (const auto ec = glz::read<OPTS>(test, buffer))
    {
        switch (ec.ec)
        {
            // Expected errors:
        case glz::error_code::no_read_input:
        case glz::error_code::unexpected_end:
        case glz::error_code::expected_quote:
        case glz::error_code::end_reached:
        case glz::error_code::expected_brace:  // minified
        case glz::error_code::expected_colon:  // minified
        case glz::error_code::expected_comma:  // minified
        case glz::error_code::elements_not_convertible_to_design:
            return 0;
        default:
            std::cerr << "JSON read error: " << glz::format_error(ec, buffer) << '\n';
            __builtin_trap();
        }
    }

    fzz::mutate(test, rng);

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
    if (data_size == 0)
        return -1;

    const std::string_view buffer{reinterpret_cast<const char*>(data), data_size};

    fzz::Test test;
    if (const auto ec = glz::read<OPTS>(test, buffer))
    {
        switch (ec.ec)
        {
            // Expected errors:
        case glz::error_code::no_read_input:
        case glz::error_code::unexpected_end:
        case glz::error_code::expected_quote:
        case glz::error_code::end_reached:
        case glz::error_code::expected_brace:  // minified
        case glz::error_code::expected_colon:  // minified
        case glz::error_code::expected_comma:  // minified
        case glz::error_code::elements_not_convertible_to_design:
            return -1;
        default:
            std::cerr << "JSON read error: " << glz::format_error(ec, buffer) << '\n';
            __builtin_trap();
        }
    }

    // Add/update fixed SENDER to the state.
    auto& sender = test.state[SENDER];
    sender.balance += 1'000'000;

    // Validate the test.
    if (test.tx.max_priority_gas_price > test.tx.max_gas_price)
        return -1;

    fzz::execute(test);

    return 0;
}
