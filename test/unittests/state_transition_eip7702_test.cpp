// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, eip7702_set_code_transaction)
{
    rev = EVMC_PRAGUE;

    constexpr auto authority = 0xca11ee_address;
    constexpr auto delegate = 0xde1e_address;
    pre.insert(delegate, {
                             .code = bytecode{OP_STOP},
                         });
    tx.to = To;
    tx.type = Transaction::Type::set_code;
    tx.authorization_list = {{.addr = delegate, .nonce = 0, .signer = authority}};
    pre.insert(*tx.to, {
                           .code = ret(0),
                       });


    expect.post[To].exists = true;
    expect.post[delegate].exists = true;
    expect.post[authority].nonce = 1;
    expect.post[authority].code = bytes{0xef, 0x01, 0x00} + hex(delegate);
}

TEST_F(state_transition, eip7702_extcodesize)
{
    rev = EVMC_PRAGUE;

    constexpr auto callee = 0xca11ee_address;
    constexpr auto delegate = 0xde1e_address;
    pre.insert(callee, {
                           .nonce = 1,
                           .code = 0xef0100 + hex(delegate),
                       });
    pre.insert(delegate, {
                             .code = 1024 * OP_JUMPDEST,
                         });
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = sstore(1, push(delegate) + OP_EXTCODESIZE),
                       });

    expect.post[callee].exists = true;
    expect.post[delegate].exists = true;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x0400_bytes32;
}

TEST_F(state_transition, eip7702_transaction_from_delegated_account)
{
    rev = EVMC_PRAGUE;

    constexpr auto delegate = 0xde1e_address;
    pre[Sender].code = 0xef0100 + hex(delegate);
    pre.insert(delegate, {
                             .code = 1024 * OP_JUMPDEST,
                         });

    tx.to = To;
    pre.insert(*tx.to, {
                           .code = sstore(1, OP_CALLER),
                       });

    expect.post[delegate].exists = true;
    expect.post[*tx.to].storage[0x01_bytes32] = to_bytes32(Sender);
}

TEST_F(state_transition, eip7702_transaction_to_delegated_account)
{
    rev = EVMC_PRAGUE;

    constexpr auto delegate = 0xde1e_address;
    pre[To].code = 0xef0100 + hex(delegate);

    pre.insert(delegate, {
                             .code = sstore(1, 1),
                         });
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = sstore(1, OP_CALLER),
                       });

    expect.post[delegate].exists = true;
    expect.post[*tx.to].storage[0x01_bytes32] = to_bytes32(Sender);
}
