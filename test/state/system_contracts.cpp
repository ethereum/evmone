// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "system_contracts.hpp"
#include "host.hpp"
#include "state.hpp"

namespace evmone::state
{
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
}  // namespace evmone::state
