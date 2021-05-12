// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/instructions.h>
#include <memory>
#include <string_view>

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

class Tracer
{
    friend class VM;  // Has access the the m_next_tracer to traverse the list forward.
    std::unique_ptr<Tracer> m_next_tracer;

public:
    virtual ~Tracer() = default;

    void notify_execution_start(
        evmc_revision rev, const evmc_message& msg, bytes_view code) noexcept
    {
        on_execution_start(rev, msg, code);
        if (m_next_tracer)
            m_next_tracer->notify_execution_start(rev, msg, code);
    }

    void notify_execution_end(const evmc_result& result) noexcept  // NOLINT(misc-no-recursion)
    {
        on_execution_end(result);
        if (m_next_tracer)
            m_next_tracer->notify_execution_end(result);
    }

    void notify_instruction_start(uint32_t pc) noexcept  // NOLINT(misc-no-recursion)
    {
        on_instruction_start(pc);
        if (m_next_tracer)
            m_next_tracer->notify_instruction_start(pc);
    }

private:
    virtual void on_execution_start(
        evmc_revision rev, const evmc_message& msg, bytes_view code) noexcept = 0;
    virtual void on_instruction_start(uint32_t pc) noexcept = 0;
    virtual void on_execution_end(const evmc_result& result) noexcept = 0;
};

}  // namespace evmone
