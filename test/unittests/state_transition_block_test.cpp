// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, block_apply_withdrawal)
{
    static constexpr auto withdrawal_address = 0x8888_address;

    block.withdrawals = {{withdrawal_address, 3}};
    tx.to = To;
    expect.post[withdrawal_address].balance = intx::uint256{3} * 1'000'000'000;
}

TEST_F(state_transition, known_block_hash)
{
    block.known_block_hashes = {
        {1, 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32},
        {2, 0x0000000000000000000000000000000000000000000000000000000000000111_bytes32}};
    block.number = 5;

    const auto code =
        push(1) + OP_BLOCKHASH + push(0) + OP_SSTORE + push(2) + OP_BLOCKHASH + push(1) + OP_SSTORE;

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = code});
    expect.post[To].storage[0x00_bytes32] =
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;
    expect.post[To].storage[0x01_bytes32] =
        0x0000000000000000000000000000000000000000000000000000000000000111_bytes32;
}
