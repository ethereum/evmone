// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "statetest.hpp"
#include <gtest/gtest.h>
#include <sstream>

namespace evmone::state
{
/// Defines how to RLP-encode a Log. This is only needed to compute "logs hash".
inline bytes rlp_encode(const Log& log)
{
    return rlp::encode_tuple(log.addr, log.topics, log.data);
}
}  // namespace evmone::state

namespace evmone::test
{
namespace
{
std::string dump(state::State& state)
{
    std::ostringstream out;
    out << "POST STATE DUMP:\n";

    const auto& accounts = state.get_accounts();
    std::vector<evmc::address> addresses;
    addresses.reserve(accounts.size());
    for (const auto& [addr, _] : accounts)
        addresses.push_back(addr);
    std::sort(addresses.begin(), addresses.end());
    for (const auto& addr : addresses)
    {
        const auto& acc = accounts.at(addr);
        out << "  " << hex(addr) << ":\n";
        out << "    balance: " << to_string(acc.balance) << "\n";
        out << "    nonce: " << acc.nonce << "\n";
        out << "    storage:\n";

        for (const auto& [k, v] : acc.storage)
            out << "      " << hex(k) << ": " << hex(v.current) << "\n";
    }
    return out.str();
}
}  // namespace

void run_state_test(const StateTransitionTest& test, evmc::VM& vm)
{
    for (const auto& [rev, cases] : test.cases)
    {
        for (size_t case_index = 0; case_index != cases.size(); ++case_index)
        {
            SCOPED_TRACE(std::string{evmc::to_string(rev)} + '/' + std::to_string(case_index));
            // if (rev != EVMC_FRONTIER)
            //     continue;
            // if (case_index != 3)
            //     continue;

            const auto& expected = cases[case_index];
            const auto tx = test.multi_tx.get(expected.indexes);
            auto state = test.pre_state;

            const auto tx_logs = state::transition(state, test.block, tx, rev, vm);
            if (tx_logs.has_value())
                EXPECT_EQ(keccak256(rlp::encode(*tx_logs)), expected.logs_hash);
            else
                EXPECT_TRUE(expected.exception);

            EXPECT_EQ(state::mpt_hash(state.get_accounts()), expected.state_hash) << dump(state);
        }
    }
}
}  // namespace evmone::test
