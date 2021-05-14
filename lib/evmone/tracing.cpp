// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "tracing.hpp"
#include <evmc/hex.hpp>
#include <stack>

namespace evmone
{
namespace
{
std::string get_name(const char* const* names, uint8_t opcode)
{
    const auto name = names[opcode];
    return (name != nullptr) ? name : "0x" + evmc::hex(opcode);
}

/// @see create_histogram_tracer()
class HistogramTracer : public Tracer
{
    struct Context
    {
        const int32_t depth;
        const uint8_t* const code;
        const char* const* const opcode_names;
        uint32_t counts[256]{};

        Context(int32_t _depth, const uint8_t* _code, const char* const* _opcode_names) noexcept
          : depth{_depth}, code{_code}, opcode_names{_opcode_names}
        {}
    };

    std::stack<Context> m_contexts;
    std::ostream& m_out;

    void on_execution_start(
        evmc_revision rev, const evmc_message& msg, bytes_view code) noexcept override
    {
        m_contexts.emplace(msg.depth, code.data(), evmc_get_instruction_names_table(rev));
    }

    void on_instruction_start(uint32_t pc, const ExecutionState& /*state*/) noexcept override
    {
        auto& ctx = m_contexts.top();
        ++ctx.counts[ctx.code[pc]];
    }

    void on_execution_end(const evmc_result& /*result*/) noexcept override
    {
        const auto& ctx = m_contexts.top();
        const auto names = ctx.opcode_names;

        m_out << "--- # HISTOGRAM depth=" << ctx.depth << "\nopcode,count\n";
        for (size_t i = 0; i < std::size(ctx.counts); ++i)
        {
            if (ctx.counts[i] != 0)
                m_out << get_name(names, static_cast<uint8_t>(i)) << ',' << ctx.counts[i] << '\n';
        }

        m_contexts.pop();
    }

public:
    explicit HistogramTracer(std::ostream& out) noexcept : m_out{out} {}
};
}  // namespace

std::unique_ptr<Tracer> create_histogram_tracer(std::ostream& out)
{
    return std::make_unique<HistogramTracer>(out);
}
}  // namespace evmone
