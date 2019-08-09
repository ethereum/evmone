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
    struct storage_value
    {
        evmc_bytes32 value{};

        /// True means this value has been modified already by the current transaction.
        bool dirty{false};

        storage_value() noexcept = default;

        storage_value(const evmc_bytes32& _value, bool _dirty = false) noexcept  // NOLINT
          : value{_value}, dirty{_dirty}
        {}
    };

    bytes code;
    evmc_bytes32 codehash;
    evmc_uint256be balance;
    std::unordered_map<evmc_bytes32, storage_value> storage;

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
    struct log_record
    {
        evmc_address address;
        bytes data;
        std::vector<evmc_bytes32> topics;

        bool operator==(const log_record& other) noexcept
        {
            return address == other.address && data == other.data &&
                   std::equal(
                       topics.begin(), topics.end(), other.topics.begin(), other.topics.end());
        }
    };

    struct selfdestuct_record
    {
        evmc_address address;
        evmc_address beneficiary;

        bool operator==(const selfdestuct_record& other) noexcept
        {
            return address == other.address && beneficiary == other.beneficiary;
        }
    };

    std::unordered_map<evmc_address, MockedAccount> accounts;

    evmc_tx_context tx_context = {};

    evmc_bytes32 blockhash = {};

    evmc_result call_result = {};

    std::vector<int64_t> recorded_blockhashes;

    static constexpr auto max_recorded_account_accesses = 200;
    std::vector<evmc_address> recorded_account_accesses;

    static constexpr auto max_recorded_calls = 100;
    std::vector<evmc_message> recorded_calls;

    std::vector<log_record> recorded_logs;
    std::vector<selfdestuct_record> recorded_selfdestructs;

protected:
    std::vector<bytes> m_recorded_calls_inputs;

    void record_account_access(const evmc_address& addr)
    {
        if (recorded_account_accesses.empty())
            recorded_account_accesses.reserve(max_recorded_account_accesses);

        if (recorded_account_accesses.size() < max_recorded_account_accesses)
            recorded_account_accesses.emplace_back(addr);
    }

    bool account_exists(const evmc_address& addr) noexcept override
    {
        record_account_access(addr);
        return accounts.count(addr);
    }

    evmc_bytes32 get_storage(const evmc_address& addr, const evmc_bytes32& key) noexcept override
    {
        record_account_access(addr);
        const auto ait = accounts.find(addr);
        if (ait == accounts.end())
            return {};

        if (const auto sit = ait->second.storage.find(key); sit != ait->second.storage.end())
            return sit->second.value;
        return {};
    }

    evmc_storage_status set_storage(const evmc_address& addr, const evmc_bytes32& key,
        const evmc_bytes32& value) noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return static_cast<evmc_storage_status>(-1);

        auto& old = it->second.storage[key];

        // Follow https://eips.ethereum.org/EIPS/eip-1283 specification.
        // WARNING! This is not complete implementation as refund is not handled here.

        if (old.value == value)
            return EVMC_STORAGE_UNCHANGED;

        evmc_storage_status status;
        {
            if (!old.dirty)
            {
                old.dirty = true;
                if (is_zero(old.value))
                    status = EVMC_STORAGE_ADDED;
                else if (is_zero(value))
                    status = EVMC_STORAGE_DELETED;
                else
                    status = EVMC_STORAGE_MODIFIED;
            }
            else
                status = EVMC_STORAGE_MODIFIED_AGAIN;
        }

        old.value = value;
        return status;
    }

    evmc_uint256be get_balance(const evmc_address& addr) noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};

        return it->second.balance;
    }

    size_t get_code_size(const evmc_address& addr) noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;
        return it->second.code.size();
    }

    evmc_bytes32 get_code_hash(const evmc_address& addr) noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};
        return it->second.codehash;
    }

    size_t copy_code(const evmc_address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;

        const auto& code = it->second.code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    void selfdestruct(const evmc_address& addr, const evmc_address& beneficiary) noexcept override
    {
        record_account_access(addr);
        recorded_selfdestructs.push_back({addr, beneficiary});
    }

    evmc::result call(const evmc_message& msg) noexcept override
    {
        record_account_access(msg.destination);

        if (recorded_calls.empty())
        {
            recorded_calls.reserve(max_recorded_calls);
            m_recorded_calls_inputs.reserve(max_recorded_calls);  // Iterators will not invalidate.
        }

        if (recorded_calls.size() < max_recorded_calls)
        {
            auto& call_msg = recorded_calls.emplace_back(msg);
            if (call_msg.input_size > 0)
            {
                const auto& input_copy =
                    m_recorded_calls_inputs.emplace_back(call_msg.input_data, call_msg.input_size);
                call_msg.input_data = input_copy.data();
            }
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
