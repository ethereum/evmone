// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "errors.hpp"
#include "host.hpp"
#include "rlp.hpp"
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

void finalize(State& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<Withdrawal> withdrawals)
{
    if (block_reward.has_value())
        state.touch(coinbase).balance += *block_reward;

    if (rev >= EVMC_SPURIOUS_DRAGON)
    {
        std::erase_if(
            state.get_accounts(), [](const std::pair<const address, Account>& p) noexcept {
                const auto& acc = p.second;
                return acc.erasable && acc.is_empty();
            });
    }

    for (const auto& withdrawal : withdrawals)
        state.touch(withdrawal.recipient).balance += withdrawal.get_amount();
}

std::variant<TransactionReceipt, std::error_code> transition(
    State& state, const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm)
{
    auto& sender_acc = state.get(tx.sender);
    const auto validation_result = validate_transaction(sender_acc, block, tx, rev);

    if (holds_alternative<std::error_code>(validation_result))
        return get<std::error_code>(validation_result);

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
    // EIP-3651: Warm COINBASE.
    // This may create an empty coinbase account. The account cannot be created unconditionally
    // because this breaks old revisions.
    if (rev >= EVMC_SHANGHAI)
        host.access_account(block.coinbase);

    const auto result = host.call(build_message(tx, execution_gas_limit));

    auto gas_used = tx.gas_limit - result.gas_left;

    const auto max_refund_quotient = rev >= EVMC_LONDON ? 5 : 2;
    const auto refund_limit = gas_used / max_refund_quotient;
    const auto refund = std::min(result.gas_refund, refund_limit);
    gas_used -= refund;
    assert(gas_used > 0);

    state.get(tx.sender).balance += tx_max_cost - gas_used * effective_gas_price;
    state.touch(block.coinbase).balance += gas_used * priority_gas_price;

    // Apply destructs.
    std::erase_if(state.get_accounts(),
        [](const std::pair<const address, Account>& p) noexcept { return p.second.destructed; });

    auto receipt = TransactionReceipt{tx.kind, result.status_code, gas_used, host.take_logs(), {}};

    // Cannot put it into constructor call because logs are std::moved from host instance.
    receipt.logs_bloom_filter = compute_bloom_filter(receipt.logs);

    return receipt;
}

[[nodiscard]] bytes rlp_encode(const Log& log)
{
    return rlp::encode_tuple(log.addr, log.topics, log.data);
}

[[nodiscard]] bytes rlp_encode(const Transaction& tx)
{
    if (tx.kind == Transaction::Kind::legacy)
    {
        // rlp [nonce, gas_price, gas_limit, to, value, data, v, r, s];
        return rlp::encode_tuple(tx.nonce, tx.max_gas_price, static_cast<uint64_t>(tx.gas_limit),
            tx.to.has_value() ? tx.to.value() : bytes_view(), tx.value, tx.data, tx.v, tx.r, tx.s);
    }
    else if (tx.kind == Transaction::Kind::eip2930)
    {
        if (tx.v > 1)
            throw std::invalid_argument("`v` value for eip2930 transaction must be 0 or 1");
        // tx_type +
        // rlp [nonce, gas_price, gas_limit, to, value, data, access_list, v, r, s];
        return bytes{0x01} +  // Transaction type (eip2930 type == 1)
               rlp::encode_tuple(tx.chain_id, tx.nonce, tx.max_gas_price,
                   static_cast<uint64_t>(tx.gas_limit),
                   tx.to.has_value() ? tx.to.value() : bytes_view(), tx.value, tx.data,
                   tx.access_list, static_cast<bool>(tx.v), tx.r, tx.s);
    }
    else
    {
        if (tx.v > 1)
            throw std::invalid_argument("`v` value for eip1559 transaction must be 0 or 1");
        // tx_type +
        // rlp [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value,
        // data, access_list, sig_parity, r, s];
        return bytes{0x02} +  // Transaction type (eip1559 type == 2)
               rlp::encode_tuple(tx.chain_id, tx.nonce, tx.max_priority_gas_price, tx.max_gas_price,
                   static_cast<uint64_t>(tx.gas_limit),
                   tx.to.has_value() ? tx.to.value() : bytes_view(), tx.value, tx.data,
                   tx.access_list, static_cast<bool>(tx.v), tx.r, tx.s);
    }
}

[[nodiscard]] bytes rlp_encode(const TransactionReceipt& receipt)
{
    const auto prefix = receipt.kind == Transaction::Kind::eip1559 ? bytes{0x02} : bytes{};
    return prefix + rlp::encode_tuple(receipt.status == EVMC_SUCCESS,
                        static_cast<uint64_t>(receipt.gas_used),
                        bytes_view(receipt.logs_bloom_filter), receipt.logs);
}

}  // namespace evmone::state
