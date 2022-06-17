// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "statetest.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>

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
void run_state_test(const StateTransitionTest& test)
{
    evmc::VM vm{evmc_create_evmone(), {{"O", "0"}}};

    for (const auto& [rev, cases] : test.cases)
    {
        SCOPED_TRACE(rev);
        for (const auto& expected : cases)
        {
            const auto tx = test.multi_tx.get(expected.indexes);
            auto state = test.pre_state;

            const auto tx_logs = state::transition(state, test.block, tx, rev, vm);
            if (tx_logs.has_value())
                EXPECT_EQ(keccak256(rlp::encode(*tx_logs)), expected.logs_hash);
            else
                EXPECT_TRUE(expected.exception);

            EXPECT_EQ(state::mpt_hash(state.get_accounts()), expected.state_hash);
        }
    }
}
}  // namespace evmone::test
