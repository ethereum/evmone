// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "errors.hpp"
#include "host.hpp"
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>

namespace evmone::state
{
namespace
{
inline constexpr int64_t num_words(size_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + 31) / 32);
}

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
    static constexpr auto initcode_word_cost = 2;
    const auto is_create = !tx.to.has_value();
    const auto initcode_cost =
        is_create && rev >= EVMC_SHANGHAI ? initcode_word_cost * num_words(tx.data.size()) : 0;
    const auto tx_cost = is_create && rev >= EVMC_HOMESTEAD ? create_tx_cost : call_tx_cost;
    return tx_cost + compute_tx_data_cost(rev, tx.data) + compute_access_list_cost(tx.access_list) +
           initcode_cost;
}

/// Validates transaction and computes its execution gas limit (the amount of gas provided to EVM).
/// @return  Non-negative execution gas limit for valid transaction
///          or negative value for invalid transaction.
std::variant<int64_t, std::error_code> validate_transaction(const Account& sender_acc,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev) noexcept
{
    if (rev < EVMC_LONDON && tx.kind == Transaction::Kind::eip1559)
        return make_error_code(TX_TYPE_NOT_SUPPORTED);

    if (rev < EVMC_BERLIN && !tx.access_list.empty())
        return make_error_code(TX_TYPE_NOT_SUPPORTED);

    if (tx.max_priority_gas_price > tx.max_gas_price)
        return make_error_code(TIP_GT_FEE_CAP);  // Priority gas price is too high.

    if (tx.gas_limit > block.gas_limit)
        return make_error_code(GAS_LIMIT_REACHED);

    if (rev >= EVMC_LONDON && tx.max_gas_price < block.base_fee)
        return make_error_code(FEE_CAP_LESS_THEN_BLOCKS);

    if (!sender_acc.code.empty())
        return make_error_code(SENDER_NOT_EOA);  // Origin must not be a contract (EIP-3607).

    if (sender_acc.nonce == Account::NonceMax)
        return make_error_code(NONCE_HAS_MAX_VALUE);

    // initcode size is limited by EIP-3860.
    if (rev >= EVMC_SHANGHAI && !tx.to.has_value() && tx.data.size() > max_initcode_size)
        return make_error_code(INIT_CODE_SIZE_LIMIT_EXCEEDED);

    // Compute and check if sender has enough balance for the theoretical maximum transaction cost.
    // Note this is different from tx_max_cost computed with effective gas price later.
    // The computation cannot overflow if done with 512-bit precision.
    if (const auto tx_cost_limit_512 =
            umul(intx::uint256{tx.gas_limit}, tx.max_gas_price) + tx.value;
        sender_acc.balance < tx_cost_limit_512)
        return make_error_code(INSUFFICIENT_FUNDS);

    const auto intrinsic_cost = compute_tx_intrinsic_cost(rev, tx);
    if (intrinsic_cost > tx.gas_limit)
        return make_error_code(INTRINSIC_GAS_TOO_LOW);

    return tx.gas_limit - intrinsic_cost;
}

evmc_message build_message(const Transaction& tx, int64_t execution_gas_limit) noexcept
{
    const auto recipient = tx.to.has_value() ? *tx.to : evmc::address{};
    return {
        tx.to.has_value() ? EVMC_CALL : EVMC_CREATE,
        0,
        0,
        execution_gas_limit,
        recipient,
        tx.sender,
        tx.data.data(),
        tx.data.size(),
        intx::be::store<evmc::uint256be>(tx.value),
        {},
        recipient,
    };
}
}  // namespace

std::variant<TransactionReceipt, std::error_code> transition(
    State& state, const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm)
{
    auto& sender_acc = state.get(tx.sender);
    const auto validation_result = validate_transaction(sender_acc, block, tx, rev);

    if (holds_alternative<std::error_code>(validation_result))
    {
        // Pre EIP-158 coinbase has to be touched also for invalid tx.
        if (rev <= EVMC_TANGERINE_WHISTLE)
            state.touch(block.coinbase);
        return get<std::error_code>(validation_result);
    }

    const auto execution_gas_limit = get<int64_t>(validation_result);

    const auto base_fee = (rev >= EVMC_LONDON) ? block.base_fee : 0;
    assert(tx.max_gas_price >= base_fee);                   // Checked at the front.
    assert(tx.max_gas_price >= tx.max_priority_gas_price);  // Checked at the front.
    const auto priority_gas_price =
        std::min(tx.max_priority_gas_price, tx.max_gas_price - base_fee);
    const auto effective_gas_price = base_fee + priority_gas_price;

    assert(effective_gas_price <= tx.max_gas_price);
    const auto tx_max_cost = tx.gas_limit * effective_gas_price;

    sender_acc.balance -= tx_max_cost;  // Modify sender balance after all checks.

    Host host{rev, vm, state, block, tx};

    sender_acc.access_status = EVMC_ACCESS_WARM;  // Tx sender is always warm.
    if (tx.to.has_value())
        host.access_account(*tx.to);
    for (const auto& [a, storage_keys] : tx.access_list)
    {
        host.access_account(a);  // TODO: Return account ref.
        auto& storage = state.get(a).storage;
        for (const auto& key : storage_keys)
            storage[key].access_status = EVMC_ACCESS_WARM;
    }

    const auto result = host.call(build_message(tx, execution_gas_limit));

    auto gas_used = tx.gas_limit - result.gas_left;

    const auto max_refund_quotient = rev >= EVMC_LONDON ? 5 : 2;
    const auto refund_limit = gas_used / max_refund_quotient;
    const auto refund = std::min(result.gas_refund, refund_limit);
    gas_used -= refund;
    assert(gas_used > 0);

    state.get(tx.sender).balance += tx_max_cost - gas_used * effective_gas_price;
    state.touch(block.coinbase).balance += gas_used * priority_gas_price;

    // Apply destructs and clear erasable empty accounts.
    std::erase_if(state.get_accounts(), [rev](const std::pair<const address, Account>& p) noexcept {
        const auto& acc = p.second;
        return acc.destructed || (rev >= EVMC_SPURIOUS_DRAGON && acc.erasable && acc.is_empty());
    });

    return TransactionReceipt{gas_used, host.take_logs()};
}
}  // namespace evmone::state
