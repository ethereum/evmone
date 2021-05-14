// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "test/utils/bytecode.hpp"
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>
#include <gmock/gmock.h>

using namespace testing;

class tracing : public Test
{
private:
    evmc::VM m_baseline_vm;

protected:
    evmone::VM& vm;

    std::ostringstream trace_stream;

    tracing()
      : m_baseline_vm{evmc_create_evmone(), {{"O", "0"}}},
        vm{*static_cast<evmone::VM*>(m_baseline_vm.get_raw_pointer())}
    {}

    std::string trace(bytes_view code, int32_t depth = 0)
    {
        evmc::MockedHost host;
        evmc_message msg{};
        msg.depth = depth;
        msg.gas = 1000000;
        m_baseline_vm.execute(host, EVMC_BERLIN, msg, code.data(), code.size());
        auto result = trace_stream.str();
        trace_stream.str({});
        return result;
    }

    class OpcodeTracer final : public evmone::Tracer
    {
        std::string m_name;
        std::ostringstream& m_trace;
        const uint8_t* m_code = nullptr;

        void on_execution_start(
            evmc_revision /*rev*/, const evmc_message& /*msg*/, bytes_view code) noexcept override
        {
            m_code = code.data();
        }

        void on_execution_end(const evmc_result& /*result*/) noexcept override { m_code = nullptr; }

        void on_instruction_start(
            uint32_t pc, const evmone::ExecutionState& /*state*/) noexcept override
        {
            const auto opcode = m_code[pc];
            m_trace << m_name << pc << ":"
                    << evmc_get_instruction_names_table(EVMC_MAX_REVISION)[opcode] << " ";
        }

    public:
        explicit OpcodeTracer(tracing& parent, std::string name) noexcept
          : m_name{std::move(name)}, m_trace{parent.trace_stream}
        {}
    };
};


TEST_F(tracing, no_tracer)
{
    EXPECT_EQ(vm.get_tracer(), nullptr);
}

TEST_F(tracing, one_tracer)
{
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, ""));

    EXPECT_EQ(trace(add(1, 2)), "0:PUSH1 2:PUSH1 4:ADD ");
}

TEST_F(tracing, two_tracers)
{
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, "A"));
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, "B"));

    EXPECT_EQ(trace(add(1, 2)), "A0:PUSH1 B0:PUSH1 A2:PUSH1 B2:PUSH1 A4:ADD B4:ADD ");
}

TEST_F(tracing, three_tracers)
{
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, "A"));
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, "B"));
    vm.add_tracer(std::make_unique<OpcodeTracer>(*this, "C"));

    EXPECT_EQ(trace(dup1(0)), "A0:PUSH1 B0:PUSH1 C0:PUSH1 A2:DUP1 B2:DUP1 C2:DUP1 ");
}

TEST_F(tracing, histogram)
{
    vm.add_tracer(evmone::create_histogram_tracer(trace_stream));

    trace_stream << '\n';
    EXPECT_EQ(trace(add(0, 0)), R"(
--- # HISTOGRAM depth=0
opcode,count
ADD,1
PUSH1,2
)");
}

TEST_F(tracing, histogram_undefined_instruction)
{
    vm.add_tracer(evmone::create_histogram_tracer(trace_stream));

    trace_stream << '\n';
    EXPECT_EQ(trace(bytecode{"EF"}), R"(
--- # HISTOGRAM depth=0
opcode,count
0xef,1
)");
}

TEST_F(tracing, histogram_internal_call)
{
    vm.add_tracer(evmone::create_histogram_tracer(trace_stream));
    trace_stream << '\n';
    EXPECT_EQ(trace(push(0) + OP_DUP1 + OP_SWAP1 + OP_POP + OP_POP, 1), R"(
--- # HISTOGRAM depth=1
opcode,count
POP,2
PUSH1,1
DUP1,1
SWAP1,1
)");
}
