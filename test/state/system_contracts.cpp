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
    /// Type of requests returned by block end system call.
    /// Ignored for block start system contracts.
    Requests::Type request_type = Requests::Type::deposit;
};

/// Registered system contracts.
constexpr std::array SYSTEM_CONTRACTS_BLOCK_START{
    SystemContract{EVMC_CANCUN, BEACON_ROOTS_ADDRESS,
        [](const BlockInfo& block, const BlockHashes&) noexcept {
            return block.parent_beacon_block_root;
        }},
    SystemContract{EVMC_PRAGUE, HISTORY_STORAGE_ADDRESS,
        [](const BlockInfo& block, const BlockHashes& block_hashes) noexcept {
            return block_hashes.get_block_hash(block.number - 1);
        }},
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS_BLOCK_START,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

constexpr std::array SYSTEM_CONTRACTS_BLOCK_END{
    SystemContract{
        EVMC_PRAGUE,
        WITHDRAWAL_REQUEST_ADDRESS,
        nullptr,
        Requests::Type::withdrawal,
    },
    SystemContract{
        EVMC_PRAGUE,
        CONSOLIDATION_REQUEST_ADDRESS,
        nullptr,
        Requests::Type::consolidation,
    },
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS_BLOCK_END,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

std::pair<StateDiff, std::vector<Requests>> system_call(
    std::span<const SystemContract> system_contracts, const StateView& state_view,
    const BlockInfo& block, const state::BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm)
{
    State state{state_view};
    std::vector<Requests> requests;
    for (const auto& [since, addr, get_input, request_type] : system_contracts)
    {
        if (rev < since)
            break;  // Because entries are ordered, there are no other contracts for this revision.

        // Skip the call if the target account doesn't exist. This is by EIP-4788 spec.
        // > if no code exists at [address], the call must fail silently.
        const auto code = state_view.get_account_code(addr);
        if (code.empty())
        {
            requests.emplace_back(request_type);
            continue;
        }

        bytes32 input32;
        bytes_view input;
        if (get_input != nullptr)
        {
            input32 = get_input(block, block_hashes);
            input = input32;
        }

        const evmc_message msg{
            .kind = EVMC_CALL,
            .gas = 30'000'000,
            .recipient = addr,
            .sender = SYSTEM_ADDRESS,
            .input_data = input.data(),
            .input_size = input.size(),
        };

        const Transaction empty_tx{};
        Host host{rev, vm, state, block, block_hashes, empty_tx};
        const auto res = vm.execute(host, rev, msg, code.data(), code.size());
        assert(res.status_code == EVMC_SUCCESS);
        requests.emplace_back(request_type, bytes_view{res.output_data, res.output_size});
    }

    // TODO: Should we return empty diff if no system contracts?
    return {state.build_diff(rev), requests};
}
}  // namespace

StateDiff system_call_block_start(const StateView& state_view, const BlockInfo& block,
    const BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm)
{
    // No requests are generated in block start system calls.
    const auto [state_diff, _] =
        system_call(SYSTEM_CONTRACTS_BLOCK_START, state_view, block, block_hashes, rev, vm);
    return state_diff;
}

std::pair<StateDiff, std::vector<Requests>> system_call_block_end(const StateView& state_view,
    const BlockInfo& block, const state::BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm)
{
    return system_call(SYSTEM_CONTRACTS_BLOCK_END, state_view, block, block_hashes, rev, vm);
}
}  // namespace evmone::state
