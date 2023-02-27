// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "state.hpp"
#include <optional>
#include <unordered_set>

namespace evmone::state
{
using evmc::uint256be;

inline constexpr size_t max_code_size = 0x6000;
inline constexpr size_t max_initcode_size = 2 * max_code_size;

/// Computes the address of to-be-created contract.
///
/// Computes the new account address for the contract creation context
/// as defined by 𝐀𝐃𝐃𝐑 in Yellow Paper, 7. Contract Creation, (86).
///
/// @param sender        The address of the message sender. YP: 𝑠.
/// @param sender_nonce  The sender's nonce before the increase. YP: 𝑛.
/// @param salt          The salt for CREATE2. If null, CREATE address is computed. YP: ζ.
/// @param init_code     The contract creation init code. Value only affects CREATE2. YP: 𝐢.
/// @return              The computed address for CREATE or CREATE2 scheme.
address compute_new_account_address(const address& sender, uint64_t sender_nonce,
    const std::optional<bytes32>& salt, bytes_view init_code) noexcept;

class Host : public evmc::Host
{
    evmc_revision m_rev;
    evmc::VM& m_vm;
    State& m_state;
    const BlockInfo& m_block;
    const Transaction& m_tx;
    std::vector<Log> m_logs;

public:
    Host(evmc_revision rev, evmc::VM& vm, State& state, const BlockInfo& block,
        const Transaction& tx) noexcept
      : m_rev{rev}, m_vm{vm}, m_state{state}, m_block{block}, m_tx{tx}
    {}

    [[nodiscard]] std::vector<Log>&& take_logs() noexcept { return std::move(m_logs); }

    evmc::Result call(const evmc_message& msg) noexcept override;

private:
    [[nodiscard]] bool account_exists(const address& addr) const noexcept override;

    [[nodiscard]] bytes32 get_storage(
        const address& addr, const bytes32& key) const noexcept override;

    evmc_storage_status set_storage(
        const address& addr, const bytes32& key, const bytes32& value) noexcept override;

    [[nodiscard]] uint256be get_balance(const address& addr) const noexcept override;

    [[nodiscard]] size_t get_code_size(const address& addr) const noexcept override;

    [[nodiscard]] bytes32 get_code_hash(const address& addr) const noexcept override;

    size_t copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) const noexcept override;

    bool selfdestruct(const address& addr, const address& beneficiary) noexcept override;

    evmc::Result create(const evmc_message& msg) noexcept;

    [[nodiscard]] evmc_tx_context get_tx_context() const noexcept override;

    [[nodiscard]] bytes32 get_block_hash(int64_t block_number) const noexcept override;

    void emit_log(const address& addr, const uint8_t* data, size_t data_size,
        const bytes32 topics[], size_t topics_count) noexcept override;

public:
    evmc_access_status access_account(const address& addr) noexcept override;

private:
    evmc_access_status access_storage(const address& addr, const bytes32& key) noexcept override;

    /// Prepares message for execution.
    ///
    /// This contains mostly checks and logic related to the sender
    /// which may finally be moved to EVM.
    /// Any state modification is not reverted.
    /// @return Modified message or std::nullopt in case of EVM exception.
    std::optional<evmc_message> prepare_message(evmc_message msg);

    evmc::Result execute_message(const evmc_message& msg) noexcept;
};
}  // namespace evmone::state
