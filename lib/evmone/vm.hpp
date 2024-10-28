// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include "tracing.hpp"
#include <evmc/evmc.h>

#include <list>
#include <vector>

#if defined(_MSC_VER) && !defined(__clang__)
#define EVMONE_CGOTO_SUPPORTED 0
#else
#define EVMONE_CGOTO_SUPPORTED 1
#endif

namespace evmone
{
namespace baseline
{
class CodeAnalysis;
}

class CodeCache
{
    // TODO: Make configurable by VM API.
    static constexpr size_t SIZE = 2;

    using LRUList = std::list<std::pair<evmc::bytes32, std::shared_ptr<baseline::CodeAnalysis>>>;
    LRUList lru_list_;
    std::unordered_map<evmc::bytes32, LRUList::iterator> map_;

public:
    std::shared_ptr<baseline::CodeAnalysis> get(const evmc::bytes32& code_hash);

    void put(const evmc::bytes32& code_hash, std::shared_ptr<baseline::CodeAnalysis> code);
};

/// The evmone EVMC instance.
class VM : public evmc_vm
{
public:
    bool cgoto = EVMONE_CGOTO_SUPPORTED;
    bool validate_eof = false;

private:
    std::vector<ExecutionState> m_execution_states;
    CodeCache m_code_cache;
    std::unique_ptr<Tracer> m_first_tracer;

public:
    VM() noexcept;

    std::optional<evmc::Result> execute_cached_code(evmc::Host& host, evmc_revision rev,
        const evmc_message& msg, const evmc::bytes32& code_hash,
        const std::function<evmc::bytes_view(evmc::address)>& get_code) noexcept;

    [[nodiscard]] ExecutionState& get_execution_state(size_t depth) noexcept;

    void add_tracer(std::unique_ptr<Tracer> tracer) noexcept
    {
        // Find the first empty unique_ptr and assign the new tracer to it.
        auto* end = &m_first_tracer;
        while (*end)
            end = &(*end)->m_next_tracer;
        *end = std::move(tracer);
    }

    [[nodiscard]] Tracer* get_tracer() const noexcept { return m_first_tracer.get(); }
};
}  // namespace evmone
