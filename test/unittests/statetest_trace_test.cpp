// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/statetest/statetest.hpp>
#include <test/utils/bytecode.hpp>

using namespace evmone;
using namespace evmone::test;
using namespace evmc::literals;

/// These tests execute a predefined single-case state tests
/// and capture the trace.
class statetest_trace : public testing::Test
{
    static inline evmc::VM vm{evmc_create_evmone(), {{"trace", "1"}}};
    std::streambuf* m_orig_clog_rdbuf = nullptr;
    std::ostringstream m_trace_stream;

public:
    static constexpr auto CodeAddress = 0xc0de_address;

    StateTransitionTest test = [] {
        StateTransitionTest t;
        t.block.gas_limit = 1'000'000;
        t.pre_state.insert(CodeAddress, {.balance = 1'000'000'000});
        t.multi_tx.to = CodeAddress;
        t.multi_tx.inputs.emplace_back();
        t.multi_tx.gas_limits.emplace_back(t.block.gas_limit);
        t.multi_tx.values.emplace_back(0);
        t.cases.push_back({.rev = EVMC_SHANGHAI, .expectations{{}}});
        return t;
    }();

    bytes& code = test.pre_state.get(CodeAddress).code;
    hash256& state_hash = test.cases[0].expectations[0].state_hash;

    statetest_trace() { m_orig_clog_rdbuf = std::clog.rdbuf(m_trace_stream.rdbuf()); }
    ~statetest_trace() override { std::clog.rdbuf(m_orig_clog_rdbuf); }

    [[nodiscard]] std::string capture_trace()
    {
        run_state_test(test, vm);
        return "\n" + m_trace_stream.str();  // Leading \n makes comparison easier.
    }
};

TEST_F(statetest_trace, revert)
{
    state_hash = 0xc14bb57864ffc6c3ac14b1df0e2a183c882b8e50e7e046ac407a9958b2514410_bytes32;
    code = revert(0, 1);

    constexpr auto expected_trace = R"(
{"pc":0,"op":96,"gas":"0xef038","gasCost":"0x3","memSize":0,"stack":[],"depth":1,"refund":0,"opName":"PUSH1"}
{"pc":2,"op":96,"gas":"0xef035","gasCost":"0x3","memSize":0,"stack":["0x1"],"depth":1,"refund":0,"opName":"PUSH1"}
{"pc":4,"op":253,"gas":"0xef032","gasCost":"0x0","memSize":0,"stack":["0x1","0x0"],"depth":1,"refund":0,"opName":"REVERT"}
)";

    EXPECT_EQ(capture_trace(), expected_trace);
}
