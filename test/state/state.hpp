// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "hash_utils.hpp"
#include "precompiles.hpp"
#include "rlp.hpp"
#include <optional>
#include <unordered_set>
#include <vector>

namespace evmone::state
{
using evmc::uint256be;

class State
{
    std::unordered_map<address, Account> m_accounts;

public:
    /// Creates new account under the address.
    Account& create(const address& addr)
    {
        const auto r = m_accounts.insert({addr, {}});
        assert(r.second);
        return r.first->second;
    }

    Account& get(const address& addr)
    {
        assert(m_accounts.count(addr) == 1);
        return m_accounts.find(addr)->second;
    }

    Account* get_or_null(const address& addr)
    {
        const auto it = m_accounts.find(addr);
        if (it != m_accounts.end())
            return &it->second;
        return nullptr;
    }

    Account& get_or_create(const address& addr) { return m_accounts[addr]; }

    void touch(const address& addr) { m_accounts[addr].touched = true; }

    auto& get_accounts() { return m_accounts; }
};

struct BlockInfo
{
    int64_t number;
    int64_t timestamp;
    int64_t gas_limit;
    address coinbase;
    uint256be difficulty;
    bytes32 chain_id;
    uint64_t base_fee;
};

using AccessList = std::vector<std::pair<address, std::vector<bytes32>>>;

struct Transaction
{
    enum class Kind
    {
        legacy,
        eip1559
    };

    Kind kind = Kind::legacy;
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    uint64_t nonce;
    address sender;
    std::optional<address> to;
    intx::uint256 value;
    AccessList access_list;
};

struct Log
{
    address addr;
    bytes data;
    std::vector<hash256> topics;
};

class StateHost : public evmc::Host
{
    evmc_revision m_rev;
    evmc::VM& m_vm;
    State& m_state;
    const BlockInfo& m_block;
    const Transaction& m_tx;
    std::unordered_set<address> m_accessed_addresses;
    int64_t m_refund = 0;
    std::vector<address> m_destructs;

public:
    explicit StateHost(evmc_revision rev, evmc::VM& vm, State& state, const BlockInfo& block,
        const Transaction& tx) noexcept
      : m_rev{rev}, m_vm{vm}, m_state{state}, m_block{block}, m_tx{tx}
    {}

    [[nodiscard]] int64_t get_refund() const noexcept { return m_refund; }

    [[nodiscard]] const auto& get_destructs() const noexcept { return m_destructs; }

    bool account_exists(const address& addr) const noexcept override
    {
        const auto acc = m_state.get_or_null(addr);
        if (acc == nullptr)
            return false;
        return !acc->is_empty();
    }

    bytes32 get_storage(const address& addr, const bytes32& key) const noexcept override
    {
        const auto& acc = m_state.get(addr);
        if (const auto it = acc.storage.find(key); it != acc.storage.end())
            return it->second.current;
        return {};
    }

    evmc_storage_status set_storage(
        const address& addr, const bytes32& key, const bytes32& value) noexcept override
    {
        [[maybe_unused]] const auto old_refund = m_refund;

        // /*FIXME:*/ assert(m_rev >= EVMC_ISTANBUL);
        // const int64_t sload_gas = 800;
        // const int64_t sstore_set_gas = 20000;
        // const int64_t sstore_reset_gas = 5000;
        // const int64_t sstore_clears_schedule = 15000;

        auto& storage = m_state.get(addr).storage;

        // Follow https://eips.ethereum.org/EIPS/eip-2200 specification.

        auto& old = storage[key];

        auto status = EVMC_STORAGE_UNCHANGED;

        if (old.current == value)
        {
            status = EVMC_STORAGE_UNCHANGED;
        }
        else
        {
            if (old.original == old.current)
            {
                if (is_zero(old.original))
                {
                    status = EVMC_STORAGE_ADDED;
                    old.current = value;
                }
                else
                {
                    if (!is_zero(value))
                    {
                        status = EVMC_STORAGE_MODIFIED;
                        old.current = value;
                    }
                    else
                    {
                        status = EVMC_STORAGE_DELETED;
                        old.current = value;
                        m_refund += (m_rev >= EVMC_LONDON) ? 4800 : 15000;
                    }
                }
            }
            else  // dirty
            {
                status = EVMC_STORAGE_MODIFIED_AGAIN;
                if (!is_zero(old.original))
                {
                    if (is_zero(old.current))
                        m_refund -= (m_rev >= EVMC_LONDON) ? 4800 : 15000;
                    if (is_zero(value))
                        m_refund += (m_rev >= EVMC_LONDON) ? 4800 : 15000;
                }
                if (old.original == value)
                {
                    if (is_zero(old.original))
                        m_refund += (m_rev >= EVMC_BERLIN)         ? 19900 :
                                    (m_rev == EVMC_CONSTANTINOPLE) ? 19800 :
                                                                     19200;
                    else
                        m_refund += (m_rev >= EVMC_BERLIN) ? 2800 : 4200;
                }
                old.current = value;
            }
        }

        [[maybe_unused]] const auto sstore_refund = m_refund - old_refund;
        // std::cout << "SSTORE [" << hex(key) << "] = " << hex(value) << " (" << status << ", "
        //           << old_refund << " + " << sstore_refund << " = " << m_refund << ")\n";
        return status;
    }

    uint256be get_balance(const address& addr) const noexcept override
    {
        const auto acc = m_state.get_or_null(addr);
        if (acc == nullptr)
            return {};

        return intx::be::store<uint256be>(acc->balance);
    }

    size_t get_code_size(const address& addr) const noexcept override
    {
        const auto acc = m_state.get_or_null(addr);
        if (acc == nullptr)
            return 0;
        return acc->code.size();
    }

    bytes32 get_code_hash(const address& addr) const noexcept override
    {
        const auto acc = m_state.get_or_null(addr);
        if (acc == nullptr)
            return {};
        if (acc->is_empty())
            return {};
        return keccak256(acc->code);
    }

    size_t copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) const noexcept override
    {
        const auto acc = m_state.get_or_null(addr);
        if (acc == nullptr)
            return 0;

        const auto& code = acc->code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    void selfdestruct(const address& addr, const address& beneficiary) noexcept override
    {
        // Do not register the same selfdestruct twice.
        if (std::count(std::begin(m_destructs), std::end(m_destructs), addr) != 0)
            return;

        auto& acc = m_state.get(addr);

        // Touch it. TODO: Should be done after EIP-161.
        m_state.touch(beneficiary);

        // Immediately transfer all balance to beneficiary.
        if (addr != beneficiary && acc.balance)
        {
            auto& ben_acc = m_state.get_or_create(beneficiary);
            ben_acc.balance += acc.balance;
        }
        acc.balance = 0;

        m_destructs.push_back(addr);
        if (m_rev < EVMC_LONDON)
            m_refund += 24000;
    }

    evmc::result create(const evmc_message& msg) noexcept
    {
        assert(msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2);

        // Compute new address.
        hash256 addr_base_hash;
        if (msg.kind == EVMC_CREATE)
        {
            const auto& sender_acc = m_state.get(msg.sender);
            const bytes_view sender_address_bytes{msg.sender.bytes, sizeof(msg.sender)};
            const auto sender_nonce = msg.depth == 0 ? sender_acc.nonce - 1 : sender_acc.nonce;
            const auto rlp_list = rlp::encode_tuple(sender_address_bytes, sender_nonce);
            addr_base_hash = keccak256(rlp_list);
        }
        else
        {
            const auto init_code_hash = keccak256({msg.input_data, msg.input_size});
            uint8_t
                buffer[1 + sizeof(msg.sender) + sizeof(msg.create2_salt) + sizeof(init_code_hash)];
            static_assert(std::size(buffer) == 85);
            buffer[0] = 0xff;
            std::memcpy(&buffer[1], msg.sender.bytes, sizeof(msg.sender));
            std::memcpy(
                &buffer[1 + sizeof(msg.sender)], msg.create2_salt.bytes, sizeof(msg.create2_salt));
            std::memcpy(&buffer[1 + sizeof(msg.sender) + sizeof(msg.create2_salt)],
                init_code_hash.bytes, sizeof(init_code_hash));
            addr_base_hash = keccak256({buffer, std::size(buffer)});
        }
        evmc_address new_addr{};
        std::memcpy(new_addr.bytes, &addr_base_hash.bytes[12], sizeof(new_addr));

        m_accessed_addresses.insert(new_addr);

        if (msg.depth != 0)
        {
            if (!m_state.get(msg.sender).bump_nonce())
            {
                evmc::result result{EVMC_OUT_OF_GAS, msg.gas, nullptr, 0};  // Gas is not consumed.
                result.create_address = new_addr;
                return result;
            }
        }

        // Check collision as defined in pseudo-EIP https://github.com/ethereum/EIPs/issues/684.
        if (const auto collision_acc = m_state.get_or_null(new_addr);
            collision_acc != nullptr && !(collision_acc->nonce == 0 && collision_acc->code.empty()))
        {
            evmc::result result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
            result.create_address = new_addr;
            return result;
        }

        auto& new_acc = m_state.get_or_create(new_addr);
        if (m_rev >= EVMC_SPURIOUS_DRAGON)
            new_acc.nonce = 1;
        new_acc.storage.clear();  // In case of collision.

        const auto value = intx::be::load<intx::uint256>(msg.value);
        assert(m_state.get(msg.sender).balance >= value && "EVM must guarantee balance");
        new_acc.balance += value;  // The new account may be prefunded.
        m_state.get(msg.sender).balance -= value;

        evmc_message create_msg{};
        create_msg.kind = msg.kind;
        create_msg.depth = msg.depth;
        create_msg.gas = msg.gas;
        create_msg.recipient = new_addr;
        create_msg.sender = msg.sender;
        create_msg.value = msg.value;

        // Execution can modify the state, iterators are invalidated.
        auto result = m_vm.execute(*this, m_rev, create_msg, msg.input_data, msg.input_size);
        if (result.status_code != EVMC_SUCCESS)
        {
            result.create_address = new_addr;
            return result;
        }

        auto gas_left = result.gas_left;

        bytes_view code{result.output_data, result.output_size};
        assert(m_rev >= EVMC_SPURIOUS_DRAGON || code.size() <= 0x6000);
        if (code.size() > 0x6000)
        {
            evmc::result r{EVMC_OUT_OF_GAS, 0, nullptr, 0};
            r.create_address = new_addr;
            return r;
        }

        const auto cost = int64_t{200} * static_cast<int64_t>(code.size());
        gas_left -= cost;
        if (gas_left < 0)
        {
            evmc::result r{EVMC_OUT_OF_GAS, 0, nullptr, 0};
            r.create_address = new_addr;
            return r;
        }

        // Reject EF code.
        if (m_rev >= EVMC_LONDON && !code.empty() && code[0] == 0xEF)
        {
            evmc::result r{EVMC_OUT_OF_GAS, 0, nullptr, 0};
            r.create_address = new_addr;
            return r;
        }

        // TODO: Somehow the new_acc pointer is invalid.
        m_state.get(new_addr).code = code;

        evmc::result create_result{result.status_code, gas_left, nullptr, 0};
        create_result.create_address = new_addr;
        return create_result;
    }

    evmc::result call(const evmc_message& msg) noexcept override
    {
        // std::cout << "CALL " << msg.kind << "\n"
        //           << "  gas: " << msg.gas << "\n"
        //           << "  to: " << hex({msg.recipient.bytes, sizeof(address)}) << "\n"
        //           << "  code: " << hex({msg.code_address.bytes, sizeof(address)}) << "\n";

        auto state_snapshot = m_state;
        const auto refund_snapshot = m_refund;
        auto destructs_snapshot = m_destructs;
        auto access_addresses_snapshot = m_accessed_addresses;
        auto logs_snapshot = logs;

        evmc::result result{EVMC_INTERNAL_ERROR, 0, nullptr, 0};
        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        {
            result = create(msg);
            assert(!evmc::is_zero(result.create_address));
        }
        else
        {
            auto* code_acc = m_state.get_or_null(msg.code_address);

            if (msg.kind == EVMC_CALL)
            {
                // Touch it. TODO: Should be done after EIP-161.
                // FIXME: Should not create empty?
                m_state.touch(msg.code_address);
            }

            const auto value = intx::be::load<intx::uint256>(msg.value);
            if (msg.kind == EVMC_CALL)
            {
                // Transfer value.
                assert(m_state.get(msg.sender).balance >= value);
                // FIXME: Properly create account here.
                m_state.get(msg.recipient).balance += value;
                m_state.get(msg.sender).balance -= value;
            }

            if (auto precompiled_result = call_precompiled(m_rev, msg);
                precompiled_result.has_value())
            {
                result = std::move(*precompiled_result);
            }
            else
            {
                bytes_view code = code_acc != nullptr ? code_acc->code : bytes_view{};
                result = m_vm.execute(*this, m_rev, msg, code.data(), code.size());
            }
        }
        // std::cout << "- RESULT " << result.status_code << "\n"
        //           << "  gas: " << result.gas_left << "\n";
        if (result.status_code != EVMC_SUCCESS)
        {
            static constexpr auto addr_03 = 0x0000000000000000000000000000000000000003_address;
            const auto is_03_touched = m_state.get_or_null(addr_03) && m_state.get(addr_03).touched;

            // Revert.
            m_state = std::move(state_snapshot);
            m_refund = refund_snapshot;
            m_destructs = std::move(destructs_snapshot);
            m_accessed_addresses = std::move(access_addresses_snapshot);
            logs = std::move(logs_snapshot);

            // By EIP-2929, the new access to new created address is never reverted.
            if (!evmc::is_zero(result.create_address))
                m_accessed_addresses.insert(result.create_address);

            // The 0x03 quirk: the touch on this address is never reverted.
            if (is_03_touched)
                m_state.touch(addr_03);

            // For CREATE the nonce bump is not reverted.
            if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
            {
                if (msg.depth != 0)
                    (void)m_state.get(msg.sender).bump_nonce();
            }
        }
        return result;
    }

    evmc_tx_context get_tx_context() const noexcept override
    {
        const auto priority_gas_price =
            std::min(m_tx.max_priority_gas_price, m_tx.max_gas_price - m_block.base_fee);
        const auto effective_gas_price = m_block.base_fee + priority_gas_price;

        return evmc_tx_context{
            intx::be::store<uint256be>(effective_gas_price),
            m_tx.sender,
            m_block.coinbase,
            m_block.number,
            m_block.timestamp,
            m_block.gas_limit,
            m_block.difficulty,
            m_block.chain_id,
            uint256be{m_block.base_fee},
        };
    }

    bytes32 get_block_hash(int64_t block_number) const noexcept override
    {
        (void)block_number;
        // TODO: This is not properly implemented, but only single state test requires BLOCKHASH
        //       and is fine with any value.
        return {};
    }

    std::vector<Log> logs;

    void emit_log(const address& addr, const uint8_t* data, size_t data_size,
        const bytes32 topics[], size_t topics_count) noexcept override
    {
        Log log;
        log.addr = addr;
        log.data = bytes{data, data_size};
        for (size_t i = 0; i < topics_count; ++i)
            log.topics.push_back(topics[i]);

        logs.push_back(std::move(log));
    }

    evmc_access_status access_account(const address& addr) noexcept override
    {
        // Transaction {sender,to} are always warm.
        if (addr == m_tx.to)
            return EVMC_ACCESS_WARM;
        if (addr == m_tx.sender)
            return EVMC_ACCESS_WARM;

        // Accessing precompiled contracts is always warm.
        if (addr >= 0x0000000000000000000000000000000000000001_address &&
            addr <= 0x0000000000000000000000000000000000000009_address)
            return EVMC_ACCESS_WARM;

        // Check tx access list.
        for (const auto& [a, _] : m_tx.access_list)
        {
            if (a == addr)
                return EVMC_ACCESS_WARM;
        }

        if (m_accessed_addresses.count(addr) != 0)
            return EVMC_ACCESS_WARM;

        m_accessed_addresses.insert(addr);
        // std::cout << "COLD " << hex({addr.bytes, sizeof(addr)}) << "\n";
        return EVMC_ACCESS_COLD;
    }

    evmc_access_status access_storage(const address& addr, const bytes32& key) noexcept override
    {
        // Check tx access list.
        for (const auto& [a, storage_keys] : m_tx.access_list)
        {
            if (a == addr && std::count(storage_keys.begin(), storage_keys.end(), key) != 0)
                return EVMC_ACCESS_WARM;
        }

        auto& value = m_state.get(addr).storage[key];
        const auto access_status = value.access_status;
        value.access_status = EVMC_ACCESS_WARM;
        return access_status;
    }
};

[[nodiscard]] std::optional<std::vector<Log>> transition(
    State& state, const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm);


}  // namespace evmone::state
