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

    bool storage_cold = true;

    evmc_tx_context tx_context = {};

    evmc_bytes32 blockhash = {};

    evmc_result call_result = {};

    std::vector<int64_t> recorded_blockhashes;

    std::vector<evmc_address> recorded_account_accesses;

    std::vector<evmc_message> recorded_calls;

    struct selfdestuct_record
    {
        evmc_address address;
        evmc_address beneficiary;
    };
    std::vector<selfdestuct_record> recorded_selfdestructs;

    struct log_record
    {
        evmc_address address;
        bytes data;
        std::vector<evmc_bytes32> topics;
    };
    std::vector<log_record> recorded_logs;

private:
    bytes m_recorded_calls_input_storage;

    bool account_exists(const evmc_address& addr) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        return accounts.count(addr);
    }

    evmc_bytes32 get_storage(const evmc_address& addr, const evmc_bytes32& key) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};

        return it->second.storage[key];
    }

    evmc_storage_status set_storage(const evmc_address& addr, const evmc_bytes32& key,
        const evmc_bytes32& value) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
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
        recorded_account_accesses.emplace_back(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};

        return it->second.balance;
    }

    size_t get_code_size(const evmc_address& addr) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;
        return it->second.code.size();
    }

    evmc_bytes32 get_code_hash(const evmc_address& addr) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};
        return it->second.codehash;
    }

    size_t copy_code(const evmc_address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;

        const auto& code = it->second.code;
        const auto n = std::min(buffer_size, code.size());
        if (n > 0)
            std::copy_n(&code[code_offset], buffer_size, buffer_data);
        return n;
    }

    void selfdestruct(const evmc_address& addr, const evmc_address& beneficiary) noexcept override
    {
        recorded_account_accesses.emplace_back(addr);
        recorded_selfdestructs.push_back({addr, beneficiary});
    }

    evmc::result call(const evmc_message& msg) noexcept override
    {
        recorded_account_accesses.emplace_back(msg.destination);
        auto& call_msg = recorded_calls.emplace_back(msg);
        if (call_msg.input_size > 0)
        {
            const auto input_copy_start_pos = m_recorded_calls_input_storage.size();
            m_recorded_calls_input_storage.append(call_msg.input_data, call_msg.input_size);
            call_msg.input_data = &m_recorded_calls_input_storage[input_copy_start_pos];
        }
        return evmc::result{call_result};
    }

    evmc_tx_context get_tx_context() noexcept override { return tx_context; }

    evmc_bytes32 get_block_hash(int64_t block_number) noexcept override
    {
        recorded_blockhashes.emplace_back(block_number);
        return blockhash;
    }

    void emit_log(const evmc_address& addr, const uint8_t* data, size_t data_size,
        const evmc_bytes32 topics[], size_t topics_count) noexcept override
    {
        recorded_logs.push_back({addr, {data, data_size}, {}});
        auto& record_topics = recorded_logs.back().topics;
        record_topics.reserve(topics_count);
        std::copy_n(topics, topics_count, std::back_inserter(record_topics));
    }
};
