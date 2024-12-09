// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "system_contracts.hpp"
#include "host.hpp"
#include "state_view.hpp"

namespace evmone::state
{
namespace
{
/// Information about a registered system contract.
struct SystemContract
{
    using GetInputFn = bytes32(const BlockInfo&, const BlockHashes&) noexcept;

    evmc_revision since = EVMC_MAX_REVISION;  ///< EVM revision in which added.
    address addr;                             ///< Address of the system contract.
    GetInputFn* get_input = nullptr;          ///< How to get the input for the system call.
    Requests::Type request_type = Requests::Type::deposit;
};

/// Registered system contracts.
constexpr std::array SYSTEM_CONTRACTS{
    SystemContract{EVMC_CANCUN, BEACON_ROOTS_ADDRESS,
        [](const BlockInfo& block, const BlockHashes&) noexcept {
            return block.parent_beacon_block_root;
        }},
    SystemContract{EVMC_PRAGUE, HISTORY_STORAGE_ADDRESS,
        [](const BlockInfo& block, const BlockHashes& block_hashes) noexcept {
            return block_hashes.get_block_hash(block.number - 1);
        }},
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

constexpr std::array SYSTEM_CONTRACTS_BLOCK_END{
    SystemContract{
        EVMC_PRAGUE,
        WITHDRAWAL_REQUESTS_ADDRESS,
        nullptr,
        Requests::Type::withdrawal,
    },
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS_BLOCK_END,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

}  // namespace

StateDiff system_call(const StateView& state_view, const BlockInfo& block,
    const BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm)
{
    State state{state_view};
    for (const auto& [since, addr, get_input, _] : SYSTEM_CONTRACTS)
    {
        if (rev < since)
            break;  // Because entries are ordered, there are no other contracts for this revision.

        // Skip the call if the target account doesn't exist. This is by EIP-4788 spec.
        // > if no code exists at [address], the call must fail silently.
        const auto code = state_view.get_account_code(addr);
        if (code.empty())
            continue;

        const auto input = get_input(block, block_hashes);

        const evmc_message msg{
            .kind = EVMC_CALL,
            .gas = 30'000'000,
            .recipient = addr,
            .sender = SYSTEM_ADDRESS,
            .input_data = input.bytes,
            .input_size = std::size(input.bytes),
        };

        const Transaction empty_tx{};
        Host host{rev, vm, state, block, block_hashes, empty_tx};
        [[maybe_unused]] const auto res = vm.execute(host, rev, msg, code.data(), code.size());
        assert(res.status_code == EVMC_SUCCESS);
    }
    // TODO: Should we return empty diff if no system contracts?
    return state.build_diff(rev);
}

std::pair<StateDiff, std::vector<Requests>> system_call_block_end(const StateView& state_view,
    const BlockInfo& block, const state::BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm)
{
    State state{state_view};
    std::vector<Requests> requests;
    for (const auto& [since, addr, _, request_type] : SYSTEM_CONTRACTS_BLOCK_END)
    {
        if (rev < since)
            break;  // Because entries are ordered, there are no other contracts for this revision.

        // Skip the call if the target account doesn't exist.
        const auto code = state_view.get_account_code(addr);
        if (code.empty())
            return {};

        const evmc_message msg{
            .kind = EVMC_CALL,
            //.flags = EVMC_STATIC,
            .gas = 30'000'000,
            .recipient = addr,
            .sender = SYSTEM_ADDRESS,
            .input_data = nullptr,
            .input_size = 0,
        };

        const Transaction empty_tx{};
        Host host{rev, vm, state, block, block_hashes, empty_tx};
        [[maybe_unused]] const auto res = vm.execute(host, rev, msg, code.data(), code.size());
        assert(res.status_code == EVMC_SUCCESS);
        requests.push_back({request_type, bytes(res.output_data, res.output_size)});
    }

    return {state.build_diff(rev), requests};
}
}  // namespace evmone::state
