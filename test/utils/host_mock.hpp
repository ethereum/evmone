// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.hpp>
#include <evmc/helpers.hpp>
#include <string>
#include <unordered_map>
#include <vector>

using bytes = std::basic_string<uint8_t>;

struct MockedAccount
{
    bytes code;
    evmc_bytes32 codehash;
    evmc_uint256be balance;
    std::unordered_map<evmc_bytes32, evmc_bytes32> storage;

    /// Helper method for setting balance by numeric type.
    /// Might not be needed when intx API is improved,
    /// track https://github.com/chfast/intx/issues/105.
    void set_balance(uint64_t x) noexcept
    {
        balance = evmc_uint256be{};
        for (std::size_t i = 0; i < sizeof(x); ++i)
            balance.bytes[sizeof(balance) - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
    }
};

class MockedHost : public evmc::Host
{
public:
    std::unordered_map<evmc_address, MockedAccount> accounts;

    evmc_address last_accessed_account = {};

    bool storage_cold = true;

    evmc_tx_context tx_context = {};

    bytes log_data;
    std::vector<evmc_bytes32> log_topics;

    evmc_bytes32 blockhash = {};

    bool exists = false;
    bytes extcode = {};

    evmc_message call_msg = {};  ///< Recorded call message.
    evmc_result call_result = {};


    struct selfdestuct_record
    {
        evmc_address address;
        evmc_address beneficiary;
    };

    /// The list of recorded selfdestruct events.
    std::vector<selfdestuct_record> recorded_selfdestructs;

    bool account_exists(const evmc_address& addr) noexcept override
    {
        last_accessed_account = addr;
        return exists;
    }

    evmc_bytes32 get_storage(const evmc_address& addr, const evmc_bytes32& key) noexcept override
    {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};

        return it->second.storage[key];
    }

    evmc_storage_status set_storage(const evmc_address& addr, const evmc_bytes32& key,
        const evmc_bytes32& value) noexcept override
    {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return static_cast<evmc_storage_status>(-1);

        auto& old = it->second.storage[key];

        evmc_storage_status status;
        if (old == value)
            status = EVMC_STORAGE_UNCHANGED;
        else if (is_zero(old))
            status = EVMC_STORAGE_ADDED;
        else if (is_zero(value))
            status = EVMC_STORAGE_DELETED;
        else if (storage_cold)
            status = EVMC_STORAGE_MODIFIED;
        else
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        old = value;
        return status;
    }

    evmc_uint256be get_balance(const evmc_address& addr) noexcept override
    {
        const auto it = accounts.find(addr);
        if (it == accounts.end())  // Report that the account does not exist.
            return {};

        last_accessed_account = addr;
        return it->second.balance;
    }

    size_t get_code_size(const evmc_address& addr) noexcept override
    {
        last_accessed_account = addr;
        return extcode.size();
    }

    evmc_bytes32 get_code_hash(const evmc_address& addr) noexcept override
    {
        last_accessed_account = addr;
        auto hash = evmc_bytes32{};
        std::fill(std::begin(hash.bytes), std::end(hash.bytes), uint8_t{0xee});
        return hash;
    }

    size_t copy_code(const evmc_address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) noexcept override
    {
        last_accessed_account = addr;
        const auto n = std::min(buffer_size, extcode.size());
        if (n > 0)
            std::copy_n(&extcode[code_offset], buffer_size, buffer_data);
        return n;
    }

    void selfdestruct(const evmc_address& addr, const evmc_address& beneficiary) noexcept override
    {
        recorded_selfdestructs.push_back({addr, beneficiary});
    }

    evmc::result call(const evmc_message& msg) noexcept override
    {
        call_msg = msg;
        return evmc::result{call_result};
    }

    evmc_tx_context get_tx_context() noexcept override { return tx_context; }

    evmc_bytes32 get_block_hash(int64_t) noexcept override { return blockhash; }

    void emit_log(const evmc_address&, const uint8_t* data, size_t data_size,
        const evmc_bytes32 topics[], size_t topics_count) noexcept override
    {
        log_data.assign(data, data_size);
        log_topics.clear();
        log_topics.reserve(topics_count);
        std::copy_n(topics, topics_count, std::back_inserter(log_topics));
    }
};
