// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "statetest.hpp"
#include <gtest/gtest.h>

namespace evmone::test
{
void run_state_test(const StateTransitionTest& test, evmc::VM& vm, bool trace_summary)
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

            validate_deployed_code(state, rev);

            const auto res =
                state::transition(state, test.block, tx, rev, vm, test.block.gas_limit);

            // Finalize block with reward 0.
            state::finalize(state, rev, test.block.coinbase, 0, {}, {});

            const auto state_root = state::mpt_hash(state.get_accounts());

            if (trace_summary)
            {
                std::clog << '{';
                if (holds_alternative<state::TransactionReceipt>(res))  // if tx valid
                {
                    const auto& r = get<state::TransactionReceipt>(res);
                    if (r.status == EVMC_SUCCESS)
                        std::clog << R"("pass":true)";
                    else
                        std::clog << R"("pass":false,"error":")" << r.status << '"';
                    std::clog << R"(,"gasUsed":"0x)" << std::hex << r.gas_used << R"(",)";
                }
                std::clog << R"("stateRoot":"0x)" << hex(state_root) << "\"}\n";
            }

            if (holds_alternative<state::TransactionReceipt>(res))
                EXPECT_EQ(logs_hash(get<state::TransactionReceipt>(res).logs), expected.logs_hash);
            else
                EXPECT_TRUE(expected.exception)
                    << "unexpected invalid transaction: " << get<std::error_code>(res).message();

            EXPECT_EQ(state_root, expected.state_hash);
        }
    }
}
}  // namespace evmone::test
