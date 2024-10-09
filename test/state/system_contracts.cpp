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
    using GetInputFn = bytes_view(const BlockInfo&) noexcept;

    evmc_revision since = EVMC_MAX_REVISION;  ///< EVM revision in which added.
    address addr;                             ///< Address of the system contract.
    GetInputFn* get_input = nullptr;          ///< How to get the input for the system call.
};

/// Registered system contracts.
constexpr std::array SYSTEM_CONTRACTS{
    SystemContract{EVMC_CANCUN, BEACON_ROOTS_ADDRESS,
        [](const BlockInfo& block) noexcept { return bytes_view{block.parent_beacon_block_root}; }},
    SystemContract{EVMC_PRAGUE, HISTORY_STORAGE_ADDRESS,
        [](const BlockInfo& block) noexcept {
            return bytes_view{block.known_block_hashes.at(block.number - 1)};
        }},
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

}  // namespace

StateDiff system_call(
    const StateView& state_view, const BlockInfo& block, evmc_revision rev, evmc::VM& vm)
{
    State state{state_view};
    for (const auto& [since, addr, get_input] : SYSTEM_CONTRACTS)
    {
        if (rev < since)
            break;  // Because entries are ordered, there are no other contracts for this revision.

        // Skip the call if the target account doesn't exist. This is by EIP-4788 spec.
        // > if no code exists at [address], the call must fail silently.
        const auto code = state_view.get_account_code(addr);
        if (code.empty())
            continue;

        const auto input = get_input(block);

        const evmc_message msg{
            .kind = EVMC_CALL,
            .gas = 30'000'000,
            .recipient = addr,
            .sender = SYSTEM_ADDRESS,
            .input_data = input.data(),
            .input_size = input.size(),
        };

        const Transaction empty_tx{};
        Host host{rev, vm, state, block, empty_tx};
        [[maybe_unused]] const auto res = vm.execute(host, rev, msg, code.data(), code.size());
        assert(res.status_code == EVMC_SUCCESS);
    }
    // TODO: Should we return empty diff if no system contracts?
    return state.build_diff(rev);
}
}  // namespace evmone::state
