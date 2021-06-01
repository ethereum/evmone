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

    std::string trace(bytes_view code, int32_t depth = 0, uint32_t flags = 0)
    {
        evmc::MockedHost host;
        evmc_message msg{};
        msg.flags = flags;
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

TEST_F(tracing, trace)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    trace_stream << '\n';
    EXPECT_EQ(trace(add(2, 3)), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":96,"opName":"PUSH1","gas":1000000,"stack":[],"memorySize":0}
{"pc":2,"op":96,"opName":"PUSH1","gas":999997,"stack":["0x3"],"memorySize":0}
{"pc":4,"op":1,"opName":"ADD","gas":999994,"stack":["0x3","0x2"],"memorySize":0}
{"error":null,"gas":999991,"gasUsed":9,"output":""}
)");
}

TEST_F(tracing, trace_stack)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    const auto code = push(1) + push(2) + push(3) + push(4) + OP_ADD + OP_ADD + OP_ADD;
    trace_stream << '\n';
    EXPECT_EQ(trace(code), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":96,"opName":"PUSH1","gas":1000000,"stack":[],"memorySize":0}
{"pc":2,"op":96,"opName":"PUSH1","gas":999997,"stack":["0x1"],"memorySize":0}
{"pc":4,"op":96,"opName":"PUSH1","gas":999994,"stack":["0x1","0x2"],"memorySize":0}
{"pc":6,"op":96,"opName":"PUSH1","gas":999991,"stack":["0x1","0x2","0x3"],"memorySize":0}
{"pc":8,"op":1,"opName":"ADD","gas":999988,"stack":["0x1","0x2","0x3","0x4"],"memorySize":0}
{"pc":9,"op":1,"opName":"ADD","gas":999985,"stack":["0x1","0x2","0x7"],"memorySize":0}
{"pc":10,"op":1,"opName":"ADD","gas":999982,"stack":["0x1","0x9"],"memorySize":0}
{"error":null,"gas":999979,"gasUsed":21,"output":""}
)");
}

TEST_F(tracing, trace_error)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    const auto code = bytecode{OP_POP};
    trace_stream << '\n';
    EXPECT_EQ(trace(code), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":80,"opName":"POP","gas":1000000,"stack":[],"memorySize":0}
{"error":"stack underflow","gas":0,"gasUsed":1000000,"output":""}
)");
}

TEST_F(tracing, trace_output)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    const auto code = push(0xabcdef) + ret_top();
    trace_stream << '\n';
    EXPECT_EQ(trace(code), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":98,"opName":"PUSH3","gas":1000000,"stack":[],"memorySize":0}
{"pc":4,"op":96,"opName":"PUSH1","gas":999997,"stack":["0xabcdef"],"memorySize":0}
{"pc":6,"op":82,"opName":"MSTORE","gas":999994,"stack":["0xabcdef","0x0"],"memorySize":0}
{"pc":7,"op":96,"opName":"PUSH1","gas":999988,"stack":[],"memorySize":32}
{"pc":9,"op":96,"opName":"PUSH1","gas":999985,"stack":["0x20"],"memorySize":32}
{"pc":11,"op":243,"opName":"RETURN","gas":999982,"stack":["0x20","0x0"],"memorySize":32}
{"error":null,"gas":999982,"gasUsed":18,"output":"0000000000000000000000000000000000000000000000000000000000abcdef"}
)");
}

TEST_F(tracing, trace_revert)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    const auto code = mstore(0, 0x0e4404) + push(3) + push(29) + OP_REVERT;
    trace_stream << '\n';
    EXPECT_EQ(trace(code), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":98,"opName":"PUSH3","gas":1000000,"stack":[],"memorySize":0}
{"pc":4,"op":96,"opName":"PUSH1","gas":999997,"stack":["0xe4404"],"memorySize":0}
{"pc":6,"op":82,"opName":"MSTORE","gas":999994,"stack":["0xe4404","0x0"],"memorySize":0}
{"pc":7,"op":96,"opName":"PUSH1","gas":999988,"stack":[],"memorySize":32}
{"pc":9,"op":96,"opName":"PUSH1","gas":999985,"stack":["0x3"],"memorySize":32}
{"pc":11,"op":253,"opName":"REVERT","gas":999982,"stack":["0x3","0x1d"],"memorySize":32}
{"error":"revert","gas":999982,"gasUsed":18,"output":"0e4404"}
)");
}

TEST_F(tracing, trace_create)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    trace_stream << '\n';
    EXPECT_EQ(trace({}, 2), R"(
{"depth":2,"rev":"Berlin","static":false}
{"error":null,"gas":1000000,"gasUsed":0,"output":""}
)");
}

TEST_F(tracing, trace_static)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    trace_stream << '\n';
    EXPECT_EQ(trace({}, 2, EVMC_STATIC), R"(
{"depth":2,"rev":"Berlin","static":true}
{"error":null,"gas":1000000,"gasUsed":0,"output":""}
)");
}

TEST_F(tracing, trace_undefined_instruction)
{
    vm.add_tracer(evmone::create_instruction_tracer(trace_stream));

    const auto code = bytecode{} + OP_JUMPDEST + "EF";
    trace_stream << '\n';
    EXPECT_EQ(trace(code), R"(
{"depth":0,"rev":"Berlin","static":false}
{"pc":0,"op":91,"opName":"JUMPDEST","gas":1000000,"stack":[],"memorySize":0}
{"pc":1,"op":239,"opName":"0xef","gas":999999,"stack":[],"memorySize":0}
{"error":"undefined instruction","gas":0,"gasUsed":1000000,"output":""}
)");
}
