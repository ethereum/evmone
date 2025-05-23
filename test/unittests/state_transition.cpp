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

    // Default expectation (coinbase is added later for valid txs only).
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

    const auto res = test::transition(state, block, block_hashes, tx, rev, selected_vm,
        block.gas_limit, static_cast<int64_t>(state::max_blob_gas_per_block(rev)));
    test::finalize(state, rev, block.coinbase, block_reward, block.ommers, block.withdrawals);
    const auto& post = state;

    if (const auto expected_error = make_error_code(expect.tx_error))
    {
        ASSERT_TRUE(holds_alternative<std::error_code>(res))
            << "tx expected to be invalid with error: " << expected_error.message();
        const auto tx_error = std::get<std::error_code>(res);
        EXPECT_EQ(tx_error, expected_error)
            << tx_error.message() << " vs " << expected_error.message();

        EXPECT_EQ(post, pre) << "failed transaction has modified the state";
    }
    else
    {
        ASSERT_TRUE(holds_alternative<TransactionReceipt>(res))
            << std::get<std::error_code>(res).message();
        const auto& receipt = std::get<TransactionReceipt>(res);

        EXPECT_EQ(receipt.status, expect.status);
        if (expect.gas_used.has_value())
        {
            EXPECT_EQ(receipt.gas_used, *expect.gas_used);
        }
        // Update default expectations - valid transaction means coinbase exists unless explicitly
        // requested otherwise
        if (!expect.post.contains(Coinbase))
            expect.post[Coinbase].exists = true;
    }

    if (trace)
    {
        if (expect.trace.starts_with('\n'))  // It's easier to define expected trace with \n.
            expect.trace.remove_prefix(1);
        EXPECT_EQ(trace_capture->get_capture(), expect.trace);
    }

    for (const auto& [addr, expected_acc] : expect.post)
    {
        const auto ait = post.find(addr);
        if (ait == post.end())
        {
            EXPECT_FALSE(expected_acc.exists) << addr << ": should not exist";
            continue;
        }
        EXPECT_TRUE(expected_acc.exists) << addr << ": should exist";

        const auto& acc = ait->second;
        if (expected_acc.nonce.has_value())
        {
            EXPECT_EQ(acc.nonce, *expected_acc.nonce) << addr << ": wrong nonce";
        }
        if (expected_acc.balance.has_value())
        {
            EXPECT_EQ(acc.balance, *expected_acc.balance)
                << addr << ": balance " << to_string(acc.balance) << " vs "
                << to_string(*expected_acc.balance);
        }
        if (expected_acc.code.has_value())
        {
            EXPECT_EQ(acc.code, *expected_acc.code) << addr << ": wrong code";
        }
        for (const auto& [key, expected_value] : expected_acc.storage)
        {
            // Lookup storage values. Map non-existing ones to 0.
            const auto sit = acc.storage.find(key);
            const auto& value = sit != acc.storage.end() ? sit->second : bytes32{};
            EXPECT_EQ(value, expected_value) << addr << ": wrong storage " << key;
        }
        for (const auto& [key, value] : acc.storage)
        {
            // Find unexpected storage keys. This will also report entries with value 0.
            EXPECT_TRUE(expected_acc.storage.contains(key))
                << addr << ": unexpected storage " << key << "=" << value;
        }
    }

    for (const auto& [addr, _] : post)
    {
        EXPECT_TRUE(expect.post.contains(addr)) << addr << ": should not exist";
    }

    if (expect.state_hash)
    {
        EXPECT_EQ(mpt_hash(post), *expect.state_hash);
    }

    if (!export_file_path.empty())
        export_state_test(res, post);
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

void state_transition::export_state_test(
    const std::variant<TransactionReceipt, std::error_code>& res, const TestState& post)
{
    json::json j;
    auto& jt = j[export_test_name];

    auto& jenv = jt["env"];
    jenv["currentNumber"] = hex0x(block.number);
    jenv["currentTimestamp"] = hex0x(block.timestamp);
    jenv["currentGasLimit"] = hex0x(block.gas_limit);
    jenv["currentCoinbase"] = hex0x(block.coinbase);
    jenv["currentBaseFee"] = hex0x(block.base_fee);
    jenv["currentRandom"] = hex0x(block.prev_randao);

    jt["pre"] = to_json(pre);

    auto& jtx = jt["transaction"];
    if (tx.to.has_value())
        jtx["to"] = hex0x(*tx.to);
    jtx["sender"] = hex0x(tx.sender);
    jtx["secretKey"] = hex0x(SenderSecretKey);
    jtx["nonce"] = hex0x(tx.nonce);
    if (tx.type >= Transaction::Type::eip1559)
    {
        jtx["maxFeePerGas"] = hex0x(tx.max_gas_price);
        jtx["maxPriorityFeePerGas"] = hex0x(tx.max_priority_gas_price);
    }
    else
    {
        assert(tx.max_gas_price == tx.max_priority_gas_price);
        jtx["gasPrice"] = hex0x(tx.max_gas_price);
    }

    if (tx.type == Transaction::Type::initcodes)
    {
        auto& jinitcodes = jtx["initcodes"] = json::json::array();
        for (const auto& initcode : tx.initcodes)
            jinitcodes.emplace_back(hex0x(initcode));
    }

    jtx["data"][0] = hex0x(tx.data);
    jtx["gasLimit"][0] = hex0x(tx.gas_limit);
    jtx["value"][0] = hex0x(tx.value);

    // Force `accessLists` output even if empty.
    if (tx.type >= Transaction::Type::access_list)
        jtx["accessLists"][0] = json::json::array();

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

    if (tx.type == Transaction::Type::blob)
    {
        jtx["maxFeePerBlobGas"] = hex0x(tx.max_blob_gas_price);
        jtx["blobVersionedHashes"] = json::json::array();
        for (const auto& blob_hash : tx.blob_hashes)
        {
            jtx["blobVersionedHashes"].emplace_back(hex0x(blob_hash));
        }
    }

    if (!tx.authorization_list.empty())
    {
        auto& ja = jtx["authorizationList"];
        for (const auto& [chain_id, addr, nonce, signer, r, s, y_parity] : tx.authorization_list)
        {
            json::json je;
            je["chainId"] = hex0x(chain_id);
            je["address"] = hex0x(addr);
            je["nonce"] = hex0x(nonce);
            je["v"] = hex0x(y_parity);
            je["r"] = hex0x(r);
            je["s"] = hex0x(s);
            if (signer.has_value())
                je["signer"] = hex0x(*signer);
            ja.emplace_back(std::move(je));
        }
    }


    auto& jpost = jt["post"][to_test_fork_name(rev)][0];
    jpost["indexes"] = {{"data", 0}, {"gas", 0}, {"value", 0}};
    jpost["hash"] = hex0x(mpt_hash(post));

    if (holds_alternative<std::error_code>(res))
    {
        jpost["expectException"] =
            get_invalid_tx_message(static_cast<ErrorCode>(std::get<std::error_code>(res).value()));
        jpost["logs"] = hex0x(logs_hash(std::vector<Log>()));
    }
    else
    {
        jpost["logs"] = hex0x(logs_hash(std::get<TransactionReceipt>(res).logs));
    }

    std::ofstream{export_file_path} << std::setw(2) << j;
}
}  // namespace evmone::test
