// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_ckzg.hpp"
#include <c_kzg_4844.h>
#include <intx/intx.hpp>
#include <cstring>

using namespace intx;

namespace evmone::state
{
ExecutionResult ckzg_point_evaluation_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept
{
    static constexpr auto BLS_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_u256;

    assert(max_output_size >= 64);

    uint8_t input_buffer[192]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));


    bool ok;
    KZGCommitment commitment;
    Bytes32 z;
    Bytes32 y;
    Bytes48 proof;
    KZGSettings settings;
    verify_kzg_proof(&ok, &commitment, &z, &y, &proof, &settings);

    intx::be::unsafe::store(output_buf, uint256{FIELD_ELEMENTS_PER_BLOB});
    intx::be::unsafe::store(output_buf + 32, BLS_MODULUS);
    return {EVMC_SUCCESS, 64};
}
}  // namespace evmone::state
