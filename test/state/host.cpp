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

    // In Berlin this is handled in access_storage().
    if (m_rev < EVMC_BERLIN)
        m_state.journal_storage_change(addr, key, storage_slot);
    storage_slot.current = value;  // Update current value.
    return status;
}

uint256be Host::get_balance(const address& addr) const noexcept
{
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr) ? intx::be::store<uint256be>(acc->balance) : uint256be{};
}

namespace
{
/// For EXTCODE* instructions if the target is an EOF account, then only return EF00.
/// While we only do this if the caller is legacy, it is not a problem doing this
/// unconditionally, because EOF contracts dot no have EXTCODE* instructions.
bytes_view extcode(bytes_view code) noexcept
{
    return is_eof_container(code) ? code.substr(0, 2) : code;
}
}  // namespace

size_t Host::get_code_size(const address& addr) const noexcept
{
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr) ? extcode(acc->code).size() : 0;
}

bytes32 Host::get_code_hash(const address& addr) const noexcept
{
    // TODO: Cache code hash. It will be needed also to compute the MPT hash.
    const auto* const acc = m_state.find(addr);
    return (acc != nullptr && !acc->is_empty()) ? keccak256(extcode(acc->code)) : bytes32{};
}

size_t Host::copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
    size_t buffer_size) const noexcept
{
    const auto* const acc = m_state.find(addr);
    const auto code = (acc != nullptr) ? extcode(acc->code) : bytes_view{};
    const auto code_slice = code.substr(std::min(code_offset, code.size()));
    const auto num_bytes = std::min(buffer_size, code_slice.size());
    std::copy_n(code_slice.begin(), num_bytes, buffer_data);
    return num_bytes;
}

bool Host::selfdestruct(const address& addr, const address& beneficiary) noexcept
{
    if (m_state.find(beneficiary) == nullptr)
        m_state.journal_create(beneficiary, false);
    auto& acc = m_state.get(addr);
    const auto balance = acc.balance;
    auto& beneficiary_acc = m_state.touch(beneficiary);

    m_state.journal_balance_change(beneficiary, beneficiary_acc.balance);
    m_state.journal_balance_change(addr, balance);

    if (m_rev >= EVMC_CANCUN && !acc.just_created)
    {
        // EIP-6780:
        // "SELFDESTRUCT is executed in a transaction that is not the same
        // as the contract invoking SELFDESTRUCT was created"
        acc.balance = 0;
        beneficiary_acc.balance += balance;  // Keep balance if acc is the beneficiary.

        // Return "selfdestruct not registered".
        // In practice this affects only refunds before Cancun.
        return false;
    }

    // Transfer may happen multiple times per single account as account's balance
    // can be increased with a call following previous selfdestruct.
    beneficiary_acc.balance += balance;
    acc.balance = 0;  // Zero balance if acc is the beneficiary.

    // Mark the destruction if not done already.
    if (!acc.destructed)
    {
        m_state.journal_destruct(addr);
        acc.destructed = true;
        return true;
    }
    return false;
}

address compute_create_address(const address& sender, uint64_t sender_nonce) noexcept
{
    // TODO: Compute CREATE address without using RLP library.
    const auto rlp_list = rlp::encode_tuple(sender, sender_nonce);
    const auto base_hash = keccak256(rlp_list);
    address addr;
    std::copy_n(&base_hash.bytes[sizeof(base_hash) - sizeof(addr)], sizeof(addr), addr.bytes);
    return addr;
}

address compute_create2_address(
    const address& sender, const bytes32& salt, bytes_view init_code) noexcept
{
    const auto init_code_hash = keccak256(init_code);
    uint8_t buffer[1 + sizeof(sender) + sizeof(salt) + sizeof(init_code_hash)];
    static_assert(std::size(buffer) == 85);
    auto it = std::begin(buffer);
    *it++ = 0xff;
    it = std::copy_n(sender.bytes, sizeof(sender), it);
    it = std::copy_n(salt.bytes, sizeof(salt), it);
    std::copy_n(init_code_hash.bytes, sizeof(init_code_hash), it);
    const auto base_hash = keccak256({buffer, std::size(buffer)});
    address addr;
    std::copy_n(&base_hash.bytes[sizeof(base_hash) - sizeof(addr)], sizeof(addr), addr.bytes);
    return addr;
}

address compute_eofcreate_address(
    const address& sender, const bytes32& salt, bytes_view initcontainer) noexcept
{
    const auto initcontainer_hash = keccak256(initcontainer);
    const auto buffer_size = 1 + sizeof(sender) + sizeof(salt) + sizeof(initcontainer_hash);
    bytes buffer;
    buffer.reserve(buffer_size);
    buffer += uint8_t{0xff};
    buffer += bytes_view{sender.bytes, std::size(sender.bytes)};
    buffer += bytes_view{salt.bytes, std::size(salt.bytes)};
    buffer += bytes_view{initcontainer_hash.bytes, std::size(initcontainer_hash.bytes)};

    const auto addr_base_hash = keccak256(buffer);

    evmc_address new_addr{};
    std::copy_n(&addr_base_hash.bytes[12], sizeof(new_addr), new_addr.bytes);
    return new_addr;
}

std::optional<evmc_message> Host::prepare_message(evmc_message msg)
{
    if (msg.depth == 0 || msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2 ||
        msg.kind == EVMC_EOFCREATE)
    {
        auto& sender_acc = m_state.get(msg.sender);
        const auto sender_nonce = sender_acc.nonce;

        // EIP-2681 (already checked for depth 0 during transaction validation).
        if (sender_nonce == Account::NonceMax)
            return {};  // Light early exception.

        if (msg.depth != 0)
            m_state.journal_bump_nonce(msg.sender);
        ++sender_acc.nonce;  // Bump sender nonce.

        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2 || msg.kind == EVMC_EOFCREATE)
        {
            // Compute and set the address of the account being created.
            assert(msg.recipient == address{});
            assert(msg.code_address == address{});
            if (msg.kind == EVMC_CREATE)
                msg.recipient = compute_create_address(msg.sender, sender_nonce);
            else if (msg.kind == EVMC_CREATE2)
            {
                msg.recipient = compute_create2_address(
                    msg.sender, msg.create2_salt, {msg.input_data, msg.input_size});
            }
            else
            {
                assert(msg.kind == EVMC_EOFCREATE);
                const bytes_view initcontainer{msg.code, msg.code_size};
                msg.recipient =
                    compute_eofcreate_address(msg.sender, msg.create2_salt, initcontainer);
            }

            // By EIP-2929, the access to new created address is never reverted.
            access_account(msg.recipient);
        }
    }

    return msg;
}

evmc::Result Host::create(const evmc_message& msg) noexcept
{
    assert(msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2 || msg.kind == EVMC_EOFCREATE);

    // Check collision as defined in pseudo-EIP https://github.com/ethereum/EIPs/issues/684.
    // All combinations of conditions (nonce, code, storage) are tested.
    // TODO(EVMC): Add specific error codes for creation failures.
    if (const auto collision_acc = m_state.find(msg.recipient);
        collision_acc != nullptr && (collision_acc->nonce != 0 || !collision_acc->code.empty()))
        return evmc::Result{EVMC_FAILURE};

    // TODO: msg.recipient lookup is done 3x here.
    const bool exists = m_state.find(msg.recipient) != nullptr;
    auto& new_acc = m_state.get_or_insert(msg.recipient);
    m_state.journal_create(msg.recipient, exists);
    assert(new_acc.nonce == 0);
    if (m_rev >= EVMC_SPURIOUS_DRAGON)
        new_acc.nonce = 1;  // No need to journal: create revert will 0 the nonce.

    new_acc.just_created = true;

    // Clear the new account storage, but keep the access status (from tx access list).
    // This is only needed for tests and cannot happen in real networks.
    for (auto& [k, v] : new_acc.storage) [[unlikely]]
    {
        m_state.journal_storage_change(msg.recipient, k, v);
        v = StorageValue{.access_status = v.access_status};
    }

    auto& sender_acc = m_state.get(msg.sender);  // TODO: Duplicated account lookup.
    const auto value = intx::be::load<intx::uint256>(msg.value);
    assert(sender_acc.balance >= value && "EVM must guarantee balance");
    m_state.journal_balance_change(msg.sender, sender_acc.balance);
    m_state.journal_balance_change(msg.recipient, new_acc.balance);
    sender_acc.balance -= value;
    new_acc.balance += value;  // The new account may be prefunded.

    auto create_msg = msg;
    const auto initcode = (msg.kind == EVMC_EOFCREATE ? bytes_view{msg.code, msg.code_size} :
                                                        bytes_view{msg.input_data, msg.input_size});
    if (msg.kind != EVMC_EOFCREATE)
    {
        create_msg.input_data = nullptr;
        create_msg.input_size = 0;
    }

    auto result = m_vm.execute(*this, m_rev, create_msg, initcode.data(), initcode.size());
    if (result.status_code != EVMC_SUCCESS)
    {
        result.create_address = msg.recipient;
        return result;
    }

    auto gas_left = result.gas_left;
    assert(gas_left >= 0);

    const bytes_view code{result.output_data, result.output_size};

    // for EOFCREATE successful result is guaranteed to be non-empty
    // because container section is not allowed to be empty
    assert(msg.kind != EVMC_EOFCREATE || result.status_code != EVMC_SUCCESS || !code.empty());

    if (m_rev >= EVMC_SPURIOUS_DRAGON && code.size() > max_code_size)
        return evmc::Result{EVMC_FAILURE};

    // Code deployment cost.
    const auto cost = std::ssize(code) * 200;
    gas_left -= cost;
    if (gas_left < 0)
    {
        return (m_rev == EVMC_FRONTIER) ?
                   evmc::Result{EVMC_SUCCESS, result.gas_left, result.gas_refund, msg.recipient} :
                   evmc::Result{EVMC_FAILURE};
    }

    if (!code.empty() && code[0] == 0xEF)
    {
        if (m_rev >= EVMC_PRAGUE)
        {
            // Only EOFCREATE/TXCREATE is allowed to deploy code starting with EF.
            assert(msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2);
            return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE};
        }
        else if (m_rev >= EVMC_LONDON)
        {
            // EIP-3541: Reject EF code.
            return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE};
        }
    }

    new_acc.code = code;

    return evmc::Result{result.status_code, gas_left, result.gas_refund, msg.recipient};
}

evmc::Result Host::execute_message(const evmc_message& msg) noexcept
{
    if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2 || msg.kind == EVMC_EOFCREATE)
        return create(msg);

    if (msg.kind == EVMC_CALL)
    {
        const auto exists = m_state.find(msg.recipient) != nullptr;
        if (!exists)
            m_state.journal_create(msg.recipient, exists);
    }

    assert(msg.kind != EVMC_CALL || evmc::address{msg.recipient} == msg.code_address);
    auto* const dst_acc =
        (msg.kind == EVMC_CALL) ? &m_state.touch(msg.recipient) : m_state.find(msg.code_address);

    if (msg.kind == EVMC_CALL && !evmc::is_zero(msg.value))
    {
        // Transfer value: sender → recipient.
        // The sender's balance is already checked therefore the sender account must exist.
        const auto value = intx::be::load<intx::uint256>(msg.value);
        assert(m_state.get(msg.sender).balance >= value);
        m_state.journal_balance_change(msg.sender, m_state.get(msg.sender).balance);
        m_state.journal_balance_change(msg.recipient, dst_acc->balance);
        m_state.get(msg.sender).balance -= value;
        dst_acc->balance += value;
    }

    if (is_precompile(m_rev, msg.code_address))
        return call_precompile(m_rev, msg);

    const auto code = dst_acc != nullptr ? bytes_view{dst_acc->code} : bytes_view{};
    return m_vm.execute(*this, m_rev, msg, code.data(), code.size());
}

evmc::Result Host::call(const evmc_message& orig_msg) noexcept
{
    const auto msg = prepare_message(orig_msg);
    if (!msg.has_value())
        return evmc::Result{EVMC_FAILURE, orig_msg.gas};  // Light exception.

    const auto logs_checkpoint = m_logs.size();
    const auto state_checkpoint = m_state.checkpoint();

    auto result = execute_message(*msg);

    if (result.status_code != EVMC_SUCCESS)
    {
        static constexpr auto addr_03 = 0x03_address;
        auto* const acc_03 = m_state.find(addr_03);
        const auto is_03_touched = acc_03 != nullptr && acc_03->erase_if_empty;

        // Revert.
        m_state.rollback(state_checkpoint);
        m_logs.resize(logs_checkpoint);

        // The 0x03 quirk: the touch on this address is never reverted.
        if (is_03_touched && m_rev >= EVMC_SPURIOUS_DRAGON)
            m_state.touch(addr_03);
    }
    return result;
}

evmc_tx_context Host::get_tx_context() const noexcept
{
    // TODO: The effective gas price is already computed in transaction validation.
    // TODO: The effective gas price calculation is broken for system calls (gas price 0).
    assert(m_tx.max_gas_price >= m_block.base_fee || m_tx.max_gas_price == 0);
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
        intx::be::store<uint256be>(m_block.blob_base_fee),
        m_tx.blob_hashes.data(),
        m_tx.blob_hashes.size(),
    };
}

bytes32 Host::get_block_hash(int64_t block_number) const noexcept
{
    if (const auto& it = m_block.known_block_hashes.find(block_number);
        it != m_block.known_block_hashes.end())
        return it->second;

    // Convention for testing: if the block hash in unknown return the predefined "fake" value.
    // https://github.com/ethereum/go-ethereum/blob/v1.12.2/tests/state_test_util.go#L432
    const auto s = std::to_string(block_number);
    return keccak256({reinterpret_cast<const uint8_t*>(s.data()), s.size()});
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

    auto& acc = m_state.get_or_insert(addr, {.erase_if_empty = true});

    if (acc.access_status == EVMC_ACCESS_WARM || is_precompile(m_rev, addr))
        return EVMC_ACCESS_WARM;

    m_state.journal_access_account(addr);
    acc.access_status = EVMC_ACCESS_WARM;
    return EVMC_ACCESS_COLD;
}

evmc_access_status Host::access_storage(const address& addr, const bytes32& key) noexcept
{
    auto& storage_slot = m_state.get(addr).storage[key];
    m_state.journal_storage_change(addr, key, storage_slot);
    return std::exchange(storage_slot.access_status, EVMC_ACCESS_WARM);
}


evmc::bytes32 Host::get_transient_storage(const address& addr, const bytes32& key) const noexcept
{
    const auto& acc = m_state.get(addr);
    const auto it = acc.transient_storage.find(key);
    return it != acc.transient_storage.end() ? it->second : bytes32{};
}

void Host::set_transient_storage(
    const address& addr, const bytes32& key, const bytes32& value) noexcept
{
    auto& slot = m_state.get(addr).transient_storage[key];
    m_state.journal_transient_storage_change(addr, key, slot);
    slot = value;
}
}  // namespace evmone::state
