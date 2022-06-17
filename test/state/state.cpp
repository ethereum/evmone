// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>

namespace evmone::state
{
namespace
{
int64_t compute_tx_data_cost(evmc_revision rev, bytes_view data) noexcept
{
    constexpr int64_t zero_byte_cost = 4;
    const int64_t nonzero_byte_cost = rev >= EVMC_ISTANBUL ? 16 : 68;
    int64_t cost = 0;
    for (const auto b : data)
        cost += (b == 0) ? zero_byte_cost : nonzero_byte_cost;
    return cost;
}

int64_t compute_access_list_cost(const AccessList& access_list) noexcept
{
    static constexpr auto storage_key_cost = 1900;
    static constexpr auto address_cost = 2400;

    int64_t cost = 0;
    for (const auto& a : access_list)
        cost += address_cost + static_cast<int64_t>(a.second.size()) * storage_key_cost;
    return cost;
}

int64_t compute_tx_intrinsic_cost(evmc_revision rev, const Transaction& tx) noexcept
{
    static constexpr auto call_tx_cost = 21000;
    static constexpr auto create_tx_cost = 53000;
    const bool is_create = !tx.to.has_value();
    assert(rev >= EVMC_HOMESTEAD || !is_create);
    const auto tx_cost = is_create ? create_tx_cost : call_tx_cost;
    return tx_cost + compute_tx_data_cost(rev, tx.data) + compute_access_list_cost(tx.access_list);
}
}  // namespace

std::optional<std::vector<Log>> transition(
    State& state, const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm)
{
    if (rev < EVMC_LONDON && tx.kind == Transaction::Kind::eip1559)
        return {};

    if (rev < EVMC_BERLIN && !tx.access_list.empty())
        return {};

    if (tx.max_gas_price < tx.max_priority_gas_price)
        return {};  // tip too high

    if (block.gas_limit < tx.gas_limit)
        return {};

    if (!state.get(tx.sender).code.empty())
        return {};  // Tx origin must not be a contract (EIP-3607).

    const auto base_fee = (rev >= EVMC_LONDON) ? block.base_fee : 0;

    if (tx.max_gas_price < base_fee)
        return {};

    // FIXME: The effective_gas_price should be used.
    const auto tx_max_cost = intx::uint512{tx.gas_limit} * intx::uint512{tx.max_gas_price};
    if (state.get(tx.sender).balance < tx_max_cost)
        return {};

    const auto execution_gas_limit = tx.gas_limit - compute_tx_intrinsic_cost(rev, tx);
    if (execution_gas_limit < 0)
        return {};

    state.get(tx.sender).balance -= static_cast<intx::uint256>(tx_max_cost);

    if (state.get(tx.sender).balance < tx.value)
    {
        state.get(tx.sender).balance += static_cast<intx::uint256>(tx_max_cost);
        return {};  // FIXME: sender balance is wrong.
    }

    // Bump sender nonce. This must be the last transaction validity check.
    [[maybe_unused]] const auto nonce_ok = state.get(tx.sender).bump_nonce();
    assert(nonce_ok);  // TODO: Not tested by state tests.

    const auto state_snapshot = state;

    StateHost host{rev, vm, state, block, tx};

    const auto value_be = intx::be::store<evmc::uint256be>(tx.value);

    evmc::result result{EVMC_INTERNAL_ERROR, 0, nullptr, 0};
    if (!tx.to.has_value())  // CREATE
    {
        evmc_message msg{EVMC_CREATE, 0, 0, execution_gas_limit, {}, tx.sender, tx.data.data(),
            tx.data.size(), value_be, {}, {}};
        result = host.create(msg);
    }
    else
    {
        state.get(tx.sender).balance -= tx.value;
        state.get_or_create(*tx.to).balance += tx.value;
        state.touch(*tx.to);
        evmc_message msg{EVMC_CALL, 0, 0, execution_gas_limit, *tx.to, tx.sender, tx.data.data(),
            tx.data.size(), value_be, {}, *tx.to};
        if (auto precompiled_result = call_precompiled(rev, msg); precompiled_result.has_value())
        {
            result = std::move(*precompiled_result);
        }
        else
        {
            bytes_view code = state.get(*tx.to).code;
            result = vm.execute(host, rev, msg, code.data(), code.size());
        }
    }

    const auto gas_left = result.gas_left;

    if (result.status_code != EVMC_SUCCESS)
        state = state_snapshot;

    auto gas_used = tx.gas_limit - gas_left;

    const auto max_refund_quotient = rev >= EVMC_LONDON ? 5 : 2;
    const auto refund_limit = gas_used / max_refund_quotient;
    const auto refund_raw = (result.status_code == EVMC_SUCCESS) ? host.get_refund() : 0;
    const auto refund = std::min(refund_raw, refund_limit);
    gas_used -= refund;

    assert(tx.max_gas_price >= base_fee);                   // Checked at the front.
    assert(tx.max_gas_price >= tx.max_priority_gas_price);  // Checked at the front.

    const auto priority_gas_price =
        std::min(tx.max_priority_gas_price, tx.max_gas_price - base_fee);
    const auto effective_gas_price = base_fee + priority_gas_price;

    const auto sender_fee = gas_used * effective_gas_price;
    const auto producer_pay = gas_used * priority_gas_price;

    state.get(tx.sender).balance += static_cast<intx::uint256>(tx_max_cost);
    state.get(tx.sender).balance -= sender_fee;
    state.get_or_create(block.coinbase).balance += producer_pay;

    // Touch COINBASE. TODO: Should be done after EIP-161.
    state.touch(block.coinbase);

    auto& accounts = state.get_accounts();

    // Apply destructs.
    if (result.status_code == EVMC_SUCCESS)
    {
        for (const auto& addr : host.get_destructs())
            accounts.erase(addr);
    }

    if (rev >= EVMC_SPURIOUS_DRAGON)  // TODO: The enable point is very poorly tested.
    {
        // Clear touched empty accounts.
        for (auto it = accounts.begin(); it != accounts.end();)
        {
            const auto& acc = it->second;
            if (acc.touched && acc.is_empty())
                accounts.erase(it++);
            else
                ++it;
        }
    }

    if (result.status_code != EVMC_SUCCESS)
        host.logs.clear();

    return std::move(host.logs);
}
}  // namespace evmone::state
