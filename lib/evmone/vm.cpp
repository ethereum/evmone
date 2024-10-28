// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// @file
/// EVMC instance (class VM) and entry point of evmone is defined here.

#include "vm.hpp"
#include "advanced_execution.hpp"
#include "baseline.hpp"
#include <evmone/evmone.h>
#include <cassert>
#include <iostream>

namespace evmone
{
namespace
{
void destroy(evmc_vm* vm) noexcept
{
    assert(vm != nullptr);
    delete static_cast<VM*>(vm);
}

constexpr evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept
{
    return EVMC_CAPABILITY_EVM1;
}

evmc_set_option_result set_option(evmc_vm* c_vm, char const* c_name, char const* c_value) noexcept
{
    const auto name = (c_name != nullptr) ? std::string_view{c_name} : std::string_view{};
    const auto value = (c_value != nullptr) ? std::string_view{c_value} : std::string_view{};
    auto& vm = *static_cast<VM*>(c_vm);

    if (name == "advanced")
    {
        c_vm->execute = evmone::advanced::execute;
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "cgoto")
    {
#if EVMONE_CGOTO_SUPPORTED
        if (value == "no")
        {
            vm.cgoto = false;
            return EVMC_SET_OPTION_SUCCESS;
        }
        return EVMC_SET_OPTION_INVALID_VALUE;
#else
        return EVMC_SET_OPTION_INVALID_NAME;
#endif
    }
    else if (name == "trace")
    {
        vm.add_tracer(create_instruction_tracer(std::clog));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "histogram")
    {
        vm.add_tracer(create_histogram_tracer(std::clog));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "validate_eof")
    {
        vm.validate_eof = true;
        return EVMC_SET_OPTION_SUCCESS;
    }
    return EVMC_SET_OPTION_INVALID_NAME;
}

}  // namespace


VM::VM() noexcept
  : evmc_vm{
        EVMC_ABI_VERSION,
        "evmone",
        PROJECT_VERSION,
        evmone::destroy,
        evmone::baseline::execute,
        evmone::get_capabilities,
        evmone::set_option,
    }
{
    m_execution_states.reserve(1025);
}

ExecutionState& VM::get_execution_state(size_t depth) noexcept
{
    // Vector already has the capacity for all possible depths,
    // so reallocation never happens (therefore: noexcept).
    // The ExecutionStates are lazily created because they pre-allocate EVM memory and stack.
    assert(depth < m_execution_states.capacity());
    if (m_execution_states.size() <= depth)
        m_execution_states.resize(depth + 1);
    return m_execution_states[depth];
}

std::shared_ptr<baseline::CodeAnalysis> CodeCache::get(const evmc::bytes32& code_hash)
{
    const auto it = map_.find(code_hash);
    if (it == map_.end())
        return nullptr;
    lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
    return it->second->second;
}

void CodeCache::put(const evmc::bytes32& code_hash, std::shared_ptr<baseline::CodeAnalysis> code)
{
    auto it = map_.find(code_hash);
    lru_list_.emplace_front(code_hash, std::move(code));
    if (it != map_.end())
    {
        lru_list_.erase(it->second);
        map_.erase(it);
    }
    map_[code_hash] = lru_list_.begin();

    if (map_.size() > SIZE)
    {
        auto last = lru_list_.end();
        --last;
        map_.erase(last->first);
        lru_list_.pop_back();
    }
}


EVMC_EXPORT std::optional<evmc::Result> VM::execute_cached_code(evmc::Host& host, evmc_revision rev,
    const evmc_message& msg, const evmc::bytes32& code_hash,
    const std::function<evmc::bytes_view(evmc::address)>& get_code) noexcept
{
    if (execute != static_cast<decltype(execute)>(baseline::execute))  // Only Baseline is supported
        return {};

    auto p = m_code_cache.get(code_hash);
    if (p == nullptr)
    {
        const auto code = get_code(msg.code_address);

        if (is_eof_container(code))
            return {};  // EOF not supported because CodeAnalysis don't have a copy of the code.

        p = std::make_shared<baseline::CodeAnalysis>(baseline::analyze(code, rev >= EVMC_PRAGUE));
        m_code_cache.put(code_hash, p);
    }

    const auto& ca = *p;
    return evmc::Result{
        baseline::execute(*this, evmc::Host::get_interface(), host.to_context(), rev, msg, ca)};
}

}  // namespace evmone

extern "C" {
EVMC_EXPORT evmc_vm* evmc_create_evmone() noexcept
{
    return new evmone::VM{};
}
}
