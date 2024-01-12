// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"
#include <evmone/eof.hpp>
#include <test/state/mpt_hash.hpp>
#include <test/statetest/statetest.hpp>
#include <filesystem>
#include <fstream>

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
    // Validation:

    if (rev < EVMC_LONDON)
    {
        ASSERT_EQ(block.base_fee, 0);
        ASSERT_EQ(tx.type, state::Transaction::Type::legacy);
    }
    if (tx.type == state::Transaction::Type::legacy)
    {
        ASSERT_EQ(tx.max_gas_price, tx.max_priority_gas_price);
    }

    validate_state(pre, rev);

    // Execution:

    auto state = pre;
    const auto trace = !expect.trace.empty();
    auto& selected_vm = trace ? tracing_vm : vm;

    /// Optionally enable trace capturing in form of a RAII object.
    std::optional<TraceCapture> trace_capture;
    if (trace)
        trace_capture.emplace();

    const auto res = state::transition(state, block, tx, rev, selected_vm, block.gas_limit,
        state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);

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

        // TODO: Export also tests with invalid transactions.
        return;  // Do not check anything else.
    }

    ASSERT_TRUE(holds_alternative<TransactionReceipt>(res))
        << std::get<std::error_code>(res).message();
    const auto& receipt = std::get<TransactionReceipt>(res);
    state::finalize(state, rev, block.coinbase, block_reward, block.ommers, block.withdrawals);

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

    if (expect.state_hash)
    {
        EXPECT_EQ(mpt_hash(state.get_accounts()), *expect.state_hash);
    }

    for (const auto& [addr, _] : state.get_accounts())
    {
        EXPECT_TRUE(expect.post.contains(addr)) << "unexpected account " << addr;
    }

    if (!export_file_path.empty())
        export_state_test(receipt, state);
}

namespace
{
/// Converts EVM revision to the fork name commonly used in tests.
std::string_view to_test_fork_name(evmc_revision rev) noexcept
{
    switch (rev)
    {
    case EVMC_TANGERINE_WHISTLE:
        return "EIP150";
    case EVMC_SPURIOUS_DRAGON:
        return "EIP158";
    default:
        return evmc::to_string(rev);
    }
}
}  // namespace

void state_transition::export_state_test(const TransactionReceipt& receipt, const State& post)
{
    json::json j;
    auto& jt = j[export_test_name];

    auto& jenv = jt["env"];
    jenv["currentNumber"] = hex0x(block.number);
    jenv["currentTimestamp"] = hex0x(block.timestamp);
    jenv["currentGasLimit"] = hex0x(block.gas_limit);
    jenv["currentCoinbase"] = hex0x(block.coinbase);
    jenv["currentBaseFee"] = hex0x(block.base_fee);

    jt["pre"] = to_json(pre.get_accounts());

    auto& jtx = jt["transaction"];
    if (tx.to.has_value())
        jtx["to"] = hex0x(*tx.to);
    jtx["sender"] = hex0x(tx.sender);
    jtx["secretKey"] = hex0x(SenderSecretKey);
    jtx["nonce"] = hex0x(tx.nonce);
    if (rev < EVMC_LONDON)
    {
        assert(tx.max_gas_price == tx.max_priority_gas_price);
        jtx["gasPrice"] = hex0x(tx.max_gas_price);
    }
    else
    {
        jtx["maxFeePerGas"] = hex0x(tx.max_gas_price);
        jtx["maxPriorityFeePerGas"] = hex0x(tx.max_priority_gas_price);
    }

    for (size_t i = 0; i < tx.initcodes.size(); ++i)
        jtx["initcodes"][i] = hex0x(tx.initcodes[i]);

    jtx["data"][0] = hex0x(tx.data);
    jtx["gasLimit"][0] = hex0x(tx.gas_limit);
    jtx["value"][0] = hex0x(tx.value);

    if (!tx.access_list.empty())
    {
        auto& ja = jtx["accessLists"][0];
        for (const auto& [addr, storage_keys] : tx.access_list)
        {
            json::json je;
            je["address"] = hex0x(addr);
            auto& jstorage_keys = je["storageKeys"] = json::json::array();
            for (const auto& k : storage_keys)
                jstorage_keys.emplace_back(hex0x(k));
            ja.emplace_back(std::move(je));
        }
    }

    auto& jpost = jt["post"][to_test_fork_name(rev)][0];
    jpost["indexes"] = {{"data", 0}, {"gas", 0}, {"value", 0}};
    jpost["hash"] = hex0x(mpt_hash(post.get_accounts()));
    jpost["logs"] = hex0x(logs_hash(receipt.logs));

    std::ofstream{export_file_path} << std::setw(2) << j;
}
}  // namespace evmone::test
