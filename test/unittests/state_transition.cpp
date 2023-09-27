// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

namespace evmone::test
{
void state_transition::SetUp()
{
    pre.insert(tx.sender, {.nonce = 1, .balance = tx.gas_limit * tx.max_gas_price + tx.value + 1});

    // Default expectations.
    expect.post[Coinbase].exists = true;
    expect.post[tx.sender].exists = true;
}

class TraceCapture
{
    std::streambuf* m_orig_rdbuf = nullptr;
    std::ostringstream m_trace_stream;

public:
    TraceCapture() { m_orig_rdbuf = std::clog.rdbuf(m_trace_stream.rdbuf()); }
    ~TraceCapture() { std::clog.rdbuf(m_orig_rdbuf); }
    [[maybe_unused]] std::string get_capture() const { return m_trace_stream.str(); }
};

void state_transition::TearDown()
{
    auto state = pre;
    const auto trace = !expect.trace.empty();
    auto& selected_vm = trace ? tracing_vm : vm;

    /// Optionally enable trace capturing in form of a RAII object.
    std::optional<TraceCapture> trace_capture;
    if (trace)
        trace_capture.emplace();

    const auto res = evmone::state::transition(state, block, tx, rev, selected_vm, block.gas_limit);

    if (const auto expected_error = make_error_code(expect.tx_error))
    {
        ASSERT_TRUE(holds_alternative<std::error_code>(res))
            << "tx expected to be invalid with error: " << expected_error.message();
        const auto tx_error = std::get<std::error_code>(res);
        EXPECT_EQ(tx_error, expected_error)
            << tx_error.message() << " vs " << expected_error.message();

        // TODO: Compare states carefully, they should be identical.
        EXPECT_EQ(state.get_accounts().size(), pre.get_accounts().size());
        for (const auto& [addr, acc] : state.get_accounts())
        {
            EXPECT_TRUE(pre.get_accounts().contains(addr)) << "unexpected account " << addr;
        }

        return;  // Do not check anything else.
    }

    ASSERT_TRUE(holds_alternative<TransactionReceipt>(res))
        << std::get<std::error_code>(res).message();
    const auto& receipt = std::get<TransactionReceipt>(res);
    evmone::state::finalize(
        state, rev, block.coinbase, block_reward, block.ommers, block.withdrawals);

    if (trace)
    {
        if (expect.trace.starts_with('\n'))  // It's easier to define expected trace with \n.
            expect.trace.remove_prefix(1);
        EXPECT_EQ(trace_capture->get_capture(), expect.trace);
    }

    EXPECT_EQ(receipt.status, expect.status);
    if (expect.gas_used.has_value())
    {
        EXPECT_EQ(receipt.gas_used, *expect.gas_used);
    }

    for (const auto& [addr, expected_acc] : expect.post)
    {
        const auto acc = state.find(addr);
        if (!expected_acc.exists)
        {
            EXPECT_EQ(acc, nullptr) << "account " << addr << " should not exist";
        }
        else
        {
            ASSERT_NE(acc, nullptr) << "account " << addr << " should exist";
            if (expected_acc.nonce.has_value())
            {
                EXPECT_EQ(acc->nonce, *expected_acc.nonce) << "account " << addr;
            }
            if (expected_acc.balance.has_value())
            {
                EXPECT_EQ(acc->balance, *expected_acc.balance)
                    << to_string(acc->balance) << " vs " << to_string(*expected_acc.balance)
                    << " account " << addr;
            }
            if (expected_acc.code.has_value())
            {
                EXPECT_EQ(acc->code, *expected_acc.code) << "account " << addr;
            }
            for (const auto& [key, value] : expected_acc.storage)
            {
                EXPECT_EQ(acc->storage[key].current, value) << "account " << addr << " key " << key;
            }
            for (const auto& [key, value] : acc->storage)
            {
                // Find unexpected storage keys. This will also report entries with value 0.
                EXPECT_TRUE(expected_acc.storage.contains(key))
                    << "unexpected storage key " << key << "=" << value.current << " in " << addr;
            }
        }
    }

    for (const auto& [addr, _] : state.get_accounts())
    {
        EXPECT_TRUE(expect.post.contains(addr)) << "unexpected account " << addr;
    }
}
}  // namespace evmone::test
