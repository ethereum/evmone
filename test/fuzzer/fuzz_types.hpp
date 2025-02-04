#pragma once
#include "../state/state.hpp"

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
