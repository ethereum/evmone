// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include "host_mock.hpp"

static constexpr evmc_host_interface interface = {
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.last_accessed_account = *addr;
        return e.exists;
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key) {
        return static_cast<MockedHost*>(ctx)->storage[*key];
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key, const evmc_bytes32* value) {
        auto& old = static_cast<MockedHost*>(ctx)->storage[*key];

        evmc_storage_status status;
        if (old == *value)
            status = EVMC_STORAGE_UNCHANGED;
        else if (is_zero(old))
            status = EVMC_STORAGE_ADDED;
        else if (is_zero(*value))
            status = EVMC_STORAGE_DELETED;
        else if (static_cast<MockedHost*>(ctx)->storage_cold)
            status = EVMC_STORAGE_MODIFIED;
        else
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        old = *value;
        return status;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.last_accessed_account = *addr;
        evmc_uint256be b = {};
        intx::be::store(b.bytes, e.balance);
        return b;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.last_accessed_account = *addr;
        return e.extcode.size();
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.last_accessed_account = *addr;
        auto hash = evmc_bytes32{};
        std::fill(std::begin(hash.bytes), std::end(hash.bytes), uint8_t{0xee});
        return hash;
    },
    [](evmc_context* ctx, const evmc_address* addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.last_accessed_account = *addr;
        auto n = std::min(buffer_size, e.extcode.size());
        std::copy_n(&e.extcode[code_offset], buffer_size, buffer_data);
        return n;
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_address* beneficiary) {
        static_cast<MockedHost*>(ctx)->selfdestruct_beneficiary = *beneficiary;
    },
    [](evmc_context* ctx, const evmc_message* m) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.call_msg = *m;
        return e.call_result;
    },
    [](evmc_context* ctx) { return static_cast<MockedHost*>(ctx)->tx_context; },
    [](evmc_context* ctx, int64_t) { return static_cast<MockedHost*>(ctx)->blockhash; },
    [](evmc_context* ctx, const evmc_address*, const uint8_t* data, size_t data_size,
        const evmc_bytes32 topics[], size_t topics_count) {
        auto& e = *static_cast<MockedHost*>(ctx);
        e.log_data.assign(data, data_size);
        e.log_topics.clear();
        e.log_topics.reserve(topics_count);
        std::copy_n(topics, topics_count, std::back_inserter(e.log_topics));
    },
};

MockedHost::MockedHost() noexcept : evmc_context{&interface} {}
