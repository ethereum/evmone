// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/rlp.hpp"
#include "statetest.hpp"

namespace evmone::state
{
/// Defines how to RLP-encode a Log. This is only needed to compute "logs hash".
inline bytes rlp_encode(const Log& log)
{
    return rlp::encode_tuple(log.addr, log.topics, log.data);
}
}  // namespace evmone::state

namespace evmone::test
{
hash256 logs_hash(const std::vector<state::Log>& logs)
{
    return keccak256(rlp::encode(logs));
}
}  // namespace evmone::test
