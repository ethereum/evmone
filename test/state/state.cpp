// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "../utils/stdx/utility.hpp"
#include "errors.hpp"
#include "host.hpp"
#include "rlp.hpp"
#include <evmone/eof.hpp>
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>
#include <algorithm>

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

int64_t compute_initcode_list_cost(evmc_revision rev, std::span<const bytes> initcodes) noexcept
{
    int64_t cost = 0;
    for (const auto& initcode : initcodes)
        cost += compute_tx_data_cost(rev, initcode);
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
           compute_initcode_list_cost(rev, tx.initcodes) + initcode_cost;
}

evmc_message build_message(const Transaction& tx, int64_t execution_gas_limit) noexcept
{
    const auto recipient = tx.to.has_value() ? *tx.to : evmc::address{};
    return {tx.to.has_value() ? EVMC_CALL : EVMC_CREATE, 0, 0, execution_gas_limit, recipient,
        tx.sender, tx.data.data(), tx.data.size(), intx::be::store<evmc::uint256be>(tx.value), {},
        recipient, nullptr, 0};
}
}  // namespace

Account& State::insert(const address& addr, Account account)
{
    const auto r = m_accounts.insert({addr, std::move(account)});
    assert(r.second);
    return r.first->second;
}

Account* State::find(const address& addr) noexcept
{
    const auto it = m_accounts.find(addr);
    if (it != m_accounts.end())
        return &it->second;
    return nullptr;
}

Account& State::get(const address& addr) noexcept
{
    auto acc = find(addr);
    assert(acc != nullptr);
    return *acc;
}

Account& State::get_or_insert(const address& addr, Account account)
{
    if (const auto acc = find(addr); acc != nullptr)
        return *acc;
    return insert(addr, std::move(account));
}

Account& State::touch(const address& addr)
{
    auto& acc = get_or_insert(addr, {.erase_if_empty = true});
    if (!acc.erase_if_empty && acc.is_empty())
    {
        acc.erase_if_empty = true;
        m_journal.emplace_back(JournalTouched{addr});
    }
    return acc;
}

void State::journal_balance_change(const address& addr, const intx::uint256& prev_balance)
{
    m_journal.emplace_back(JournalBalanceChange{{addr}, prev_balance});
}

void State::journal_storage_change(
    const address& addr, const bytes32& key, const StorageValue& value)
{
    m_journal.emplace_back(JournalStorageChange{{addr}, key, value.current, value.access_status});
}

void State::journal_transient_storage_change(
    const address& addr, const bytes32& key, const bytes32& value)
{
    m_journal.emplace_back(JournalTransientStorageChange{{addr}, key, value});
}

void State::journal_bump_nonce(const address& addr)
{
    m_journal.emplace_back(JournalNonceBump{addr});
}

void State::journal_create(const address& addr, bool existed)
{
    m_journal.emplace_back(JournalCreate{{addr}, existed});
}

void State::journal_destruct(const address& addr)
{
    m_journal.emplace_back(JournalDestruct{addr});
}

void State::journal_access_account(const address& addr)
{
    m_journal.emplace_back(JournalAccessAccount{addr});
}

void State::rollback(size_t checkpoint)
{
    while (m_journal.size() != checkpoint)
    {
        std::visit(
            [this](const auto& e) {
                using T = std::decay_t<decltype(e)>;
                if constexpr (std::is_same_v<T, JournalNonceBump>)
                {
                    get(e.addr).nonce -= 1;
                }
                else if constexpr (std::is_same_v<T, JournalTouched>)
                {
                    get(e.addr).erase_if_empty = false;
                }
                else if constexpr (std::is_same_v<T, JournalDestruct>)
                {
                    get(e.addr).destructed = false;
                }
                else if constexpr (std::is_same_v<T, JournalAccessAccount>)
                {
                    get(e.addr).access_status = EVMC_ACCESS_COLD;
                }
                else if constexpr (std::is_same_v<T, JournalCreate>)
                {
                    if (e.existed)
                    {
                        // This account is not always "touched". TODO: Why?
                        auto& a = get(e.addr);
                        a.nonce = 0;
                        a.code.clear();
                    }
                    else
                    {
                        // TODO: Before Spurious Dragon we don't clear empty accounts ("erasable")
                        //       so we need to delete them here explicitly.
                        //       This should be changed by tuning "erasable" flag
                        //       and clear in all revisions.
                        m_accounts.erase(e.addr);
                    }
                }
                else if constexpr (std::is_same_v<T, JournalStorageChange>)
                {
                    auto& s = get(e.addr).storage.find(e.key)->second;
                    s.current = e.prev_value;
                    s.access_status = e.prev_access_status;
                }
                else if constexpr (std::is_same_v<T, JournalTransientStorageChange>)
                {
                    auto& s = get(e.addr).transient_storage.find(e.key)->second;
                    s = e.prev_value;
                }
                else if constexpr (std::is_same_v<T, JournalBalanceChange>)
                {
                    get(e.addr).balance = e.prev_balance;
                }
                else
                {
                    // TODO(C++23): Change condition to `false` once CWG2518 is in.
                    static_assert(std::is_void_v<T>, "unhandled journal entry type");
                }
            },
            m_journal.back());
        m_journal.pop_back();
    }
}

intx::uint256 compute_blob_gas_price(uint64_t excess_blob_gas) noexcept
{
    /// A helper function approximating `factor * e ** (numerator / denominator)`.
    /// https://eips.ethereum.org/EIPS/eip-4844#helpers
    static constexpr auto fake_exponential = [](uint64_t factor, uint64_t numerator,
                                                 uint64_t denominator) noexcept {
        intx::uint256 i = 1;
        intx::uint256 output = 0;
        intx::uint256 numerator_accum = factor * denominator;
        while (numerator_accum > 0)
        {
            output += numerator_accum;
            numerator_accum = (numerator_accum * numerator) / (denominator * i);
            i += 1;
        }
        return output / denominator;
    };

    static constexpr auto MIN_BLOB_GASPRICE = 1;
    static constexpr auto BLOB_GASPRICE_UPDATE_FRACTION = 3338477;
    return fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION);
}

/// Validates transaction and computes its execution gas limit (the amount of gas provided to EVM).
/// @return  Execution gas limit or transaction validation error.
std::variant<int64_t, std::error_code> validate_transaction(const Account& sender_acc,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev, int64_t block_gas_left,
    int64_t blob_gas_left) noexcept
{
    switch (tx.type)
    {
    case Transaction::Type::blob:
        if (rev < EVMC_CANCUN)
            return make_error_code(TX_TYPE_NOT_SUPPORTED);
        if (!tx.to.has_value())
            return make_error_code(CREATE_BLOB_TX);
        if (tx.blob_hashes.empty())
            return make_error_code(EMPTY_BLOB_HASHES_LIST);

        if (tx.max_blob_gas_price < block.blob_base_fee)
            return make_error_code(FEE_CAP_LESS_THEN_BLOCKS);

        if (std::ranges::any_of(tx.blob_hashes, [](const auto& h) { return h.bytes[0] != 0x01; }))
            return make_error_code(INVALID_BLOB_HASH_VERSION);
        if (std::cmp_greater(tx.blob_gas_used(), blob_gas_left))
            return make_error_code(BLOB_GAS_LIMIT_EXCEEDED);
        break;

    case Transaction::Type::initcodes:
        if (rev < EVMC_PRAGUE)
            return make_error_code(TX_TYPE_NOT_SUPPORTED);
        if (tx.initcodes.size() > max_initcode_count)
            return make_error_code(INIT_CODE_COUNT_LIMIT_EXCEEDED);
        if (std::any_of(tx.initcodes.begin(), tx.initcodes.end(),
                [](const bytes& v) { return v.size() > max_initcode_size; }))
            return make_error_code(INIT_CODE_SIZE_LIMIT_EXCEEDED);
        break;

    default:;
    }

    switch (tx.type)
    {
    case Transaction::Type::blob:
    case Transaction::Type::initcodes:
    case Transaction::Type::eip1559:
        if (rev < EVMC_LONDON)
            return make_error_code(TX_TYPE_NOT_SUPPORTED);

        if (tx.max_priority_gas_price > tx.max_gas_price)
            return make_error_code(TIP_GT_FEE_CAP);  // Priority gas price is too high.
        [[fallthrough]];

    case Transaction::Type::access_list:
        if (rev < EVMC_BERLIN)
            return make_error_code(TX_TYPE_NOT_SUPPORTED);
        [[fallthrough]];

    case Transaction::Type::legacy:;
    }

    assert(tx.max_priority_gas_price <= tx.max_gas_price);

    if (tx.gas_limit > block_gas_left)
        return make_error_code(GAS_LIMIT_REACHED);

    if (tx.max_gas_price < block.base_fee)
        return make_error_code(FEE_CAP_LESS_THEN_BLOCKS);

    if (!sender_acc.code.empty())
        return make_error_code(SENDER_NOT_EOA);  // Origin must not be a contract (EIP-3607).

    if (sender_acc.nonce == Account::NonceMax)  // Nonce value limit (EIP-2681).
        return make_error_code(NONCE_HAS_MAX_VALUE);

    if (sender_acc.nonce < tx.nonce)
        return make_error_code(NONCE_TOO_HIGH);

    if (sender_acc.nonce > tx.nonce)
        return make_error_code(NONCE_TOO_LOW);

    // initcode size is limited by EIP-3860.
    if (rev >= EVMC_SHANGHAI && !tx.to.has_value() && tx.data.size() > max_initcode_size)
        return make_error_code(INIT_CODE_SIZE_LIMIT_EXCEEDED);

    if (rev >= EVMC_PRAGUE && !tx.to.has_value() && is_eof_container(tx.data))
        return make_error_code(EOF_CREATION_TRANSACTION);

    // Compute and check if sender has enough balance for the theoretical maximum transaction cost.
    // Note this is different from tx_max_cost computed with effective gas price later.
    // The computation cannot overflow if done with 512-bit precision.
    auto max_total_fee = umul(intx::uint256{tx.gas_limit}, tx.max_gas_price);
    max_total_fee += tx.value;

    if (tx.type == Transaction::Type::blob)
    {
        const auto total_blob_gas = tx.blob_gas_used();
        // FIXME: Can overflow uint256.
        max_total_fee += total_blob_gas * tx.max_blob_gas_price;
    }
    if (sender_acc.balance < max_total_fee)
        return make_error_code(INSUFFICIENT_FUNDS);

    const auto execution_gas_limit = tx.gas_limit - compute_tx_intrinsic_cost(rev, tx);
    if (execution_gas_limit < 0)
        return make_error_code(INTRINSIC_GAS_TOO_LOW);

    return execution_gas_limit;
}

namespace
{
/// Deletes "touched" (marked as erasable) empty accounts in the state.
void delete_empty_accounts(State& state)
{
    std::erase_if(state.get_accounts(), [](const std::pair<const address, Account>& p) noexcept {
        const auto& acc = p.second;
        return acc.erase_if_empty && acc.is_empty();
    });
}
}  // namespace

void system_call(State& state, const BlockInfo& block, evmc_revision rev, evmc::VM& vm)
{
    static constexpr auto SystemAddress = 0xfffffffffffffffffffffffffffffffffffffffe_address;
    static constexpr auto BeaconRootsAddress = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address;

    if (rev >= EVMC_CANCUN)
    {
        if (const auto acc = state.find(BeaconRootsAddress); acc != nullptr)
        {
            const evmc_message msg{
                .kind = EVMC_CALL,
                .gas = 30'000'000,
                .recipient = BeaconRootsAddress,
                .sender = SystemAddress,
                .input_data = block.parent_beacon_block_root.bytes,
                .input_size = sizeof(block.parent_beacon_block_root),
            };

            const Transaction empty_tx{};
            Host host{rev, vm, state, block, empty_tx};
            const auto& code = acc->code;
            [[maybe_unused]] const auto res = vm.execute(host, rev, msg, code.data(), code.size());
            assert(res.status_code == EVMC_SUCCESS);
            assert(acc->access_status == EVMC_ACCESS_COLD);

            // Reset storage status.
            for (auto& [_, val] : acc->storage)
            {
                val.access_status = EVMC_ACCESS_COLD;
                val.original = val.current;
            }
        }
    }
}

void finalize(State& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const Ommer> ommers,
    std::span<const Withdrawal> withdrawals)
{
    // TODO: The block reward can be represented as a withdrawal.
    if (block_reward.has_value())
    {
        const auto reward = *block_reward;
        assert(reward % 32 == 0);  // Assume block reward is divisible by 32.
        const auto reward_by_32 = reward / 32;
        const auto reward_by_8 = reward / 8;

        state.touch(coinbase).balance += reward + reward_by_32 * ommers.size();
        for (const auto& ommer : ommers)
        {
            assert(ommer.delta > 0 && ommer.delta < 8);
            state.touch(ommer.beneficiary).balance += reward_by_8 * (8 - ommer.delta);
        }
    }

    for (const auto& withdrawal : withdrawals)
        state.touch(withdrawal.recipient).balance += withdrawal.get_amount();

    // Delete potentially empty block reward recipients.
    if (rev >= EVMC_SPURIOUS_DRAGON)
        delete_empty_accounts(state);
}

std::variant<TransactionReceipt, std::error_code> transition(State& state, const BlockInfo& block,
    const Transaction& tx, evmc_revision rev, evmc::VM& vm, int64_t block_gas_left,
    int64_t blob_gas_left)
{
    auto* sender_ptr = state.find(tx.sender);

    // Validate transaction. The validation needs the sender account, so in case
    // it doesn't exist provide an empty one. The account isn't created in the state
    // to prevent the state modification in case the transaction is invalid.
    const auto validation_result =
        validate_transaction((sender_ptr != nullptr) ? *sender_ptr : Account{}, block, tx, rev,
            block_gas_left, blob_gas_left);

    if (holds_alternative<std::error_code>(validation_result))
        return get<std::error_code>(validation_result);

    // Once the transaction is valid, create new sender account.
    // The account won't be empty because its nonce will be bumped.
    auto& sender_acc = (sender_ptr != nullptr) ? *sender_ptr : state.insert(tx.sender);

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

    if (tx.type == Transaction::Type::blob)
    {
        const auto blob_fee = tx.blob_gas_used() * block.blob_base_fee;
        assert(sender_acc.balance >= blob_fee);  // Checked at the front.
        sender_acc.balance -= blob_fee;
    }

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

    sender_acc.balance += tx_max_cost - gas_used * effective_gas_price;
    state.touch(block.coinbase).balance += gas_used * priority_gas_price;

    // Apply destructs.
    std::erase_if(state.get_accounts(),
        [](const std::pair<const address, Account>& p) noexcept { return p.second.destructed; });

    // Cumulative gas used is unknown in this scope.
    TransactionReceipt receipt{tx.type, result.status_code, gas_used, {}, host.take_logs(), {}, {}};

    // Cannot put it into constructor call because logs are std::moved from host instance.
    receipt.logs_bloom_filter = compute_bloom_filter(receipt.logs);

    // Delete empty accounts after every transaction. This is strictly required until Byzantium
    // where intermediate state root hashes are part of the transaction receipt.
    // TODO: Consider limiting this only to Spurious Dragon.
    if (rev >= EVMC_SPURIOUS_DRAGON)
        delete_empty_accounts(state);

    // Post-transaction clean-up.
    // - Set accounts and their storage access status to cold.
    // - Clear the "just created" account flag.
    for (auto& [addr, acc] : state.get_accounts())
    {
        acc.transient_storage.clear();
        acc.access_status = EVMC_ACCESS_COLD;
        acc.just_created = false;
        for (auto& [key, val] : acc.storage)
        {
            val.access_status = EVMC_ACCESS_COLD;
            val.original = val.current;
        }
    }

    return receipt;
}

[[nodiscard]] bytes rlp_encode(const Log& log)
{
    return rlp::encode_tuple(log.addr, log.topics, log.data);
}

[[nodiscard]] bytes rlp_encode(const Transaction& tx)
{
    assert(tx.type <= Transaction::Type::blob);

    // TODO: Refactor this function. For all type of transactions most of the code is similar.
    if (tx.type == Transaction::Type::legacy)
    {
        // rlp [nonce, gas_price, gas_limit, to, value, data, v, r, s];
        return rlp::encode_tuple(tx.nonce, tx.max_gas_price, static_cast<uint64_t>(tx.gas_limit),
            tx.to.has_value() ? tx.to.value() : bytes_view(), tx.value, tx.data, tx.v, tx.r, tx.s);
    }
    else if (tx.type == Transaction::Type::access_list)
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
    else if (tx.type == Transaction::Type::eip1559)
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
    else  // Transaction::Type::blob
    {
        if (tx.v > 1)
            throw std::invalid_argument("`v` value for blob transaction must be 0 or 1");
        if (!tx.to.has_value())  // Blob tx has to have `to` address
            throw std::invalid_argument("`to` value for blob transaction must not be null");
        // tx_type +
        // rlp [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value,
        // data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, sig_parity, r, s];
        return bytes{stdx::to_underlying(Transaction::Type::blob)} +
               rlp::encode_tuple(tx.chain_id, tx.nonce, tx.max_priority_gas_price, tx.max_gas_price,
                   static_cast<uint64_t>(tx.gas_limit), tx.to.value(), tx.value, tx.data,
                   tx.access_list, tx.max_blob_gas_price, tx.blob_hashes, static_cast<bool>(tx.v),
                   tx.r, tx.s);
    }
}

[[nodiscard]] bytes rlp_encode(const TransactionReceipt& receipt)
{
    if (receipt.post_state.has_value())
    {
        assert(receipt.type == Transaction::Type::legacy);

        return rlp::encode_tuple(receipt.post_state.value(),
            static_cast<uint64_t>(receipt.cumulative_gas_used),
            bytes_view(receipt.logs_bloom_filter), receipt.logs);
    }
    else
    {
        const auto prefix = receipt.type == Transaction::Type::legacy ?
                                bytes{} :
                                bytes{stdx::to_underlying(receipt.type)};

        return prefix + rlp::encode_tuple(receipt.status == EVMC_SUCCESS,
                            static_cast<uint64_t>(receipt.cumulative_gas_used),
                            bytes_view(receipt.logs_bloom_filter), receipt.logs);
    }
}

[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal)
{
    return rlp::encode_tuple(withdrawal.index, withdrawal.validator_index, withdrawal.recipient,
        withdrawal.amount_in_gwei);
}

}  // namespace evmone::state
