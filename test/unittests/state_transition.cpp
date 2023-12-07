// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#ifdef _MSC_VER
// Disable warning C4996: 'getenv': This function or variable may be unsafe.
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "state_transition.hpp"
#include <evmone/eof.hpp>
#include <test/state/mpt_hash.hpp>
#include <test/statetest/statetest.hpp>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

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
    for (const auto& [addr, acc] : pre.get_accounts())
    {
        if (is_eof_container(acc.code))
        {
            ASSERT_EQ(validate_eof(rev, acc.code), EOFValidationError::success)
                << "invalid EOF in prestate at " << addr;
        }
    }

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

    for (const auto& [addr, _] : state.get_accounts())
    {
        EXPECT_TRUE(expect.post.contains(addr)) << "unexpected account " << addr;
    }

    if (const auto export_dir = std::getenv("EVMONE_EXPORT_TESTS"); export_dir != nullptr)
        export_state_test(receipt, state, export_dir);
}

namespace
{
/// Creates the file path for the exported test based on its name.
fs::path get_export_test_path(const testing::TestInfo& test_info, std::string_view export_dir)
{
    const std::string_view test_suite_name{test_info.test_suite_name()};

    const auto stem = fs::path{test_info.file()}.stem().string();
    auto filename = std::string_view{stem};
    if (filename.starts_with(test_suite_name))
        filename.remove_prefix(test_suite_name.size() + 1);
    if (filename.ends_with("_test"))
        filename.remove_suffix(5);

    const auto dir = fs::path{export_dir} / test_suite_name / filename;

    fs::create_directories(dir);
    return dir / (std::string{test_info.name()} + ".json");
}
}  // namespace

void state_transition::export_state_test(
    const TransactionReceipt& receipt, const State& post, std::string_view export_dir)
{
    const auto& test_info = *testing::UnitTest::GetInstance()->current_test_info();

    json::json j;
    auto& jt = j[test_info.name()];

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
    jtx["maxFeePerGas"] = hex0x(tx.max_gas_price);
    jtx["maxPriorityFeePerGas"] = hex0x(tx.max_priority_gas_price);

    jtx["data"][0] = hex0x(tx.data);
    jtx["gasLimit"][0] = hex0x(tx.gas_limit);
    jtx["value"][0] = hex0x(tx.value);

    auto& jpost = jt["post"][evmc::to_string(rev)][0];
    jpost["indexes"] = {{"data", 0}, {"gas", 0}, {"value", 0}};
    jpost["hash"] = hex0x(mpt_hash(post.get_accounts()));
    jpost["logs"] = hex0x(logs_hash(receipt.logs));

    std::ofstream{get_export_test_path(test_info, export_dir)} << std::setw(2) << j;
}
}  // namespace evmone::test
