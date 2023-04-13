// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, eof_invalid_initcode)
{
    // TODO: Correction of this address is not verified.
    static constexpr auto create_address = 0x864bbda5c698ac34b47a9ea3bd4228802cc5ce3b_address;

    rev = EVMC_CANCUN;
    tx.to = To;
    pre.insert(*tx.to,
        {
            .nonce = 1,
            .storage = {{0x01_bytes32, {.current = 0x01_bytes32, .original = 0x01_bytes32}}},
            .code = eof1_bytecode(create() + push(1) + OP_SSTORE + OP_STOP, 3),
        });

    EXPECT_EQ(pre.get(tx.sender).balance, 1'000'000'001);  // Fixture sanity check.

    expect.gas_used = 985407;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[tx.sender].balance =
        pre.get(tx.sender).balance -
        (block.base_fee + tx.max_priority_gas_price) * static_cast<uint64_t>(*expect.gas_used);
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;  // CREATE caller's nonce must be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
    expect.post[create_address].exists = false;
}
