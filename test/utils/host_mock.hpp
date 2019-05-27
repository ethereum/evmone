// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/helpers.hpp>
#include <intx/intx.hpp>
#include <test/utils/utils.hpp>
#include <unordered_map>

class MockedHost : public evmc_context
{
public:
    evmc_address last_accessed_account = {};

    std::unordered_map<evmc_bytes32, evmc_bytes32> storage;
    bool storage_cold = true;

    evmc_tx_context tx_context = {};

    bytes log_data;
    std::vector<evmc_bytes32> log_topics;

    evmc_address selfdestruct_beneficiary = {};

    evmc_bytes32 blockhash = {};

    bool exists = false;
    intx::uint256 balance = {};
    bytes extcode = {};

    evmc_message call_msg = {};  ///< Recorded call message.
    evmc_result call_result = {};

    MockedHost() noexcept;
};
