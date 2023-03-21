// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "host.hpp"
#include "precompiles.hpp"
#include "rlp.hpp"
#include <evmone/eof.hpp>

namespace evmone::state
{
bool Host::account_exists(const address& addr) const noexcept
{
    const auto* const acc = m_state.find(addr);
    return acc != nullptr && (m_rev < EVMC_SPURIOUS_DRAGON || !acc->is_empty());
}

bytes32 Host::get_storage(const address& addr, const bytes32& key) const noexcept
{
    const auto& acc = m_state.get(addr);
    if (const auto it = acc.storage.find(key); it != acc.storage.end())
        return it->second.current;
    return {};
}

evmc_storage_status Host::set_storage(
    const address& addr, const bytes32& key, const bytes32& value) noexcept
{
    // Follow EVMC documentation https://evmc.ethereum.org/storagestatus.html#autotoc_md3
    // and EIP-2200 specification https://eips.ethereum.org/EIPS/eip-2200.

    auto& storage_slot = m_state.get(addr).storage[key];
    const auto& [current, original, _] = storage_slot;

    const auto dirty = original != current;
    const auto restored = original == value;
    const auto current_is_zero = is_zero(current);
    const auto value_is_zero = is_zero(value);

    auto status = EVMC_STORAGE_ASSIGNED;  // All other cases.
    if (!dirty && !restored)
    {
        if (current_is_zero)
            status = EVMC_STORAGE_ADDED;  // 0 → 0 → Z
        else if (value_is_zero)
            status = EVMC_STORAGE_DELETED;  // X → X → 0
        else
            status = EVMC_STORAGE_MODIFIED;  // X → X → Z
    }
    else if (dirty && !restored)
    {
        if (current_is_zero && !value_is_zero)
            status = EVMC_STORAGE_DELETED_ADDED;  // X → 0 → Z
        else if (!current_is_zero && value_is_zero)
            status = EVMC_STORAGE_MODIFIED_DELETED;  // X → Y → 0
    }
    else if (dirty && restored)
    {
        if (current_is_zero)
            status = EVMC_STORAGE_DELETED_RESTORED;  // X → 0 → X
        else if (value_is_zero)
            status = EVMC_STORAGE_ADDED_DELETED;  // 0 → Y → 0
        else
            status = EVMC_STORAGE_MODIFIED_RESTORED;  // X → Y → X
    }

    storage_slot.current = value;  // Update current value.
    return status;
}

uint256be Host::get_balance(const address& addr) const noexcept
{
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr) ? intx::be::store<uint256be>(acc->balance) : uint256be{};
}

size_t Host::get_code_size(const address& addr) const noexcept
{
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr) ? acc->code.size() : 0;
}

bytes32 Host::get_code_hash(const address& addr) const noexcept
{
    // TODO: Cache code hash. It will be needed also to compute the MPT hash.
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr && !acc->is_empty()) ? keccak256(acc->code) : bytes32{};
}

size_t Host::copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
    size_t buffer_size) const noexcept
{
    const auto* const acc = m_state.find(addr);
    const auto code = (acc != nullptr) ? bytes_view{acc->code} : bytes_view{};
    const auto code_slice = code.substr(std::min(code_offset, code.size()));
    const auto num_bytes = std::min(buffer_size, code_slice.size());
    std::copy_n(code_slice.begin(), num_bytes, buffer_data);
    return num_bytes;
}

bool Host::selfdestruct(const address& addr, const address& beneficiary) noexcept
{
    // Touch beneficiary and transfer all balance to it.
    // This may happen multiple times per single account as account's balance
    // can be increased with a call following previous selfdestruct.
    auto& acc = m_state.get(addr);
    m_state.touch(beneficiary).balance += acc.balance;
    acc.balance = 0;  // Zero balance (this can be the beneficiary).

    // Mark the destruction if not done already.
    return !std::exchange(acc.destructed, true);
}

address compute_new_account_address(const address& sender, uint64_t sender_nonce,
    const std::optional<bytes32>& salt, bytes_view init_code) noexcept
{
    hash256 addr_base_hash;
    if (!salt.has_value())  // CREATE
    {
        // TODO: Compute CREATE address without using RLP library.
        const auto rlp_list = rlp::encode_tuple(sender, sender_nonce);
        addr_base_hash = keccak256(rlp_list);
    }
    else  // CREATE2
    {
        const auto init_code_hash = keccak256(init_code);
        uint8_t buffer[1 + sizeof(sender) + sizeof(*salt) + sizeof(init_code_hash)];
        static_assert(std::size(buffer) == 85);
        buffer[0] = 0xff;
        std::copy_n(sender.bytes, sizeof(sender), &buffer[1]);
        std::copy_n(salt->bytes, sizeof(salt->bytes), &buffer[1 + sizeof(sender)]);
        std::copy_n(init_code_hash.bytes, sizeof(init_code_hash),
            &buffer[1 + sizeof(sender) + sizeof(salt->bytes)]);
        addr_base_hash = keccak256({buffer, std::size(buffer)});
    }
    evmc_address new_addr{};
    std::copy_n(&addr_base_hash.bytes[12], sizeof(new_addr), new_addr.bytes);
    return new_addr;
}

std::optional<evmc_message> Host::prepare_message(evmc_message msg)
{
    auto& sender_acc = m_state.get(msg.sender);
    const auto sender_nonce = sender_acc.nonce;

    // Bump sender nonce.
    if (msg.depth == 0 || msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
    {
        if (sender_nonce == Account::NonceMax)
            return {};  // Light early exception, cannot happen for depth == 0.
        ++sender_acc.nonce;
    }

    if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
    {
        // Compute and fill create address.
        assert(msg.recipient == address{});
        assert(msg.code_address == address{});
        msg.recipient = compute_new_account_address(msg.sender, sender_nonce,
            (msg.kind == EVMC_CREATE2) ? std::optional{msg.create2_salt} : std::nullopt,
            {msg.input_data, msg.input_size});

        // By EIP-2929, the  access to new created address is never reverted.
        access_account(msg.recipient);
    }

    return msg;
}

evmc::Result Host::create(const evmc_message& msg) noexcept
{
    assert(msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2);

    // Check collision as defined in pseudo-EIP https://github.com/ethereum/EIPs/issues/684.
    // All combinations of conditions (nonce, code, storage) are tested.
    // TODO(EVMC): Add specific error codes for creation failures.
    if (const auto collision_acc = m_state.find(msg.recipient);
        collision_acc != nullptr && (collision_acc->nonce != 0 || !collision_acc->code.empty()))
        return evmc::Result{EVMC_FAILURE};

    auto& new_acc = m_state.get_or_insert(msg.recipient);
    assert(new_acc.nonce == 0);
    if (m_rev >= EVMC_SPURIOUS_DRAGON)
        new_acc.nonce = 1;

    // Clear the new account storage, but keep the access status (from tx access list).
    // This is only needed for tests and cannot happen in real networks.
    for (auto& [_, v] : new_acc.storage) [[unlikely]]
        v = StorageValue{.access_status = v.access_status};

    auto& sender_acc = m_state.get(msg.sender);  // TODO: Duplicated account lookup.
    const auto value = intx::be::load<intx::uint256>(msg.value);
    assert(sender_acc.balance >= value && "EVM must guarantee balance");
    sender_acc.balance -= value;
    new_acc.balance += value;  // The new account may be prefunded.

    auto create_msg = msg;
    const bytes_view initcode{msg.input_data, msg.input_size};
    create_msg.input_data = nullptr;
    create_msg.input_size = 0;

    if (m_rev >= EVMC_CANCUN && (is_eof_container(initcode) || is_eof_container(sender_acc.code)))
    {
        if (validate_eof(m_rev, initcode) != EOFValidationError::success)
            return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE};
    }

    auto result = m_vm.execute(*this, m_rev, create_msg, msg.input_data, msg.input_size);
    if (result.status_code != EVMC_SUCCESS)
    {
        result.create_address = msg.recipient;
        return result;
    }

    auto gas_left = result.gas_left;
    assert(gas_left >= 0);

    const bytes_view code{result.output_data, result.output_size};
    if (m_rev >= EVMC_SPURIOUS_DRAGON && code.size() > max_code_size)
        return evmc::Result{EVMC_FAILURE};

    // Code deployment cost.
    const auto cost = std::ssize(code) * 200;
    gas_left -= cost;
    if (gas_left < 0)
    {
        return (m_rev == EVMC_FRONTIER) ? evmc::Result{EVMC_SUCCESS, result.gas_left} :
                                          evmc::Result{EVMC_FAILURE};
    }

    if (m_rev >= EVMC_CANCUN && (is_eof_container(initcode) || is_eof_container(code)))
    {
        if (validate_eof(m_rev, code) != EOFValidationError::success)
            return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE};
    }
    else if (m_rev >= EVMC_LONDON && !code.empty() && code[0] == 0xEF)  // Reject EF code.
        return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE};

    // TODO: The new_acc pointer is invalid because of the state revert implementation,
    //       but this should change if state journal is implemented.
    m_state.get(msg.recipient).code = code;

    return evmc::Result{result.status_code, gas_left, result.gas_refund, msg.recipient};
}

evmc::Result Host::execute_message(const evmc_message& msg) noexcept
{
    if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        return create(msg);

    assert(msg.kind != EVMC_CALL || evmc::address{msg.recipient} == msg.code_address);
    auto* const dst_acc =
        (msg.kind == EVMC_CALL) ? &m_state.touch(msg.recipient) : m_state.find(msg.code_address);

    if (msg.kind == EVMC_CALL)
    {
        // Transfer value.
        const auto value = intx::be::load<intx::uint256>(msg.value);
        assert(m_state.get(msg.sender).balance >= value);
        m_state.get(msg.sender).balance -= value;
        dst_acc->balance += value;
    }

    if (auto precompiled_result = call_precompile(m_rev, msg); precompiled_result.has_value())
        return std::move(*precompiled_result);

    // Copy of the code. Revert will invalidate the account.
    const auto code = dst_acc != nullptr ? dst_acc->code : bytes{};
    return m_vm.execute(*this, m_rev, msg, code.data(), code.size());
}

evmc::Result Host::call(const evmc_message& orig_msg) noexcept
{
    const auto msg = prepare_message(orig_msg);
    if (!msg.has_value())
        return evmc::Result{EVMC_FAILURE, orig_msg.gas};  // Light exception.

    auto state_snapshot = m_state;
    auto logs_snapshot = m_logs.size();

    auto result = execute_message(*msg);

    if (result.status_code != EVMC_SUCCESS)
    {
        static constexpr auto addr_03 = 0x03_address;
        auto* const acc_03 = m_state.find(addr_03);
        const auto is_03_touched = acc_03 != nullptr && acc_03->erasable;

        // Revert.
        m_state = std::move(state_snapshot);
        m_logs.resize(logs_snapshot);

        // The 0x03 quirk: the touch on this address is never reverted.
        if (is_03_touched && m_rev >= EVMC_SPURIOUS_DRAGON)
            m_state.touch(addr_03);
    }
    return result;
}

evmc_tx_context Host::get_tx_context() const noexcept
{
    // TODO: The effective gas price is already computed in transaction validation.
    assert(m_tx.max_gas_price >= m_block.base_fee);
    const auto priority_gas_price =
        std::min(m_tx.max_priority_gas_price, m_tx.max_gas_price - m_block.base_fee);
    const auto effective_gas_price = m_block.base_fee + priority_gas_price;

    return evmc_tx_context{
        intx::be::store<uint256be>(effective_gas_price),  // By EIP-1559.
        m_tx.sender,
        m_block.coinbase,
        m_block.number,
        m_block.timestamp,
        m_block.gas_limit,
        m_block.prev_randao,
        0x01_bytes32,  // Chain ID is expected to be 1.
        uint256be{m_block.base_fee},
    };
}

bytes32 Host::get_block_hash(int64_t block_number) const noexcept
{
    (void)block_number;
    // TODO: This is not properly implemented, but only single state test requires BLOCKHASH
    //       and is fine with any value.
    return {};
}

void Host::emit_log(const address& addr, const uint8_t* data, size_t data_size,
    const bytes32 topics[], size_t topics_count) noexcept
{
    m_logs.push_back({addr, {data, data_size}, {topics, topics + topics_count}});
}

evmc_access_status Host::access_account(const address& addr) noexcept
{
    if (m_rev < EVMC_BERLIN)
        return EVMC_ACCESS_COLD;  // Ignore before Berlin.

    auto& acc = m_state.get_or_insert(addr, {.erasable = true});
    const auto status = std::exchange(acc.access_status, EVMC_ACCESS_WARM);

    // Overwrite status for precompiled contracts: they are always warm.
    if (status == EVMC_ACCESS_COLD && addr >= 0x01_address && addr <= 0x09_address)
        return EVMC_ACCESS_WARM;

    return status;
}

evmc_access_status Host::access_storage(const address& addr, const bytes32& key) noexcept
{
    return std::exchange(m_state.get(addr).storage[key].access_status, EVMC_ACCESS_WARM);
}
}  // namespace evmone::state
