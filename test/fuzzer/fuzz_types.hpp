#pragma once
#include "../state/state.hpp"
#include <glaze/glaze.hpp>

namespace fzz
{
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

}  // namespace fzz

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
