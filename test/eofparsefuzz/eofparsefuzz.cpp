// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const evmone::bytes_view eof{data, data_size};
    if (evmone::validate_eof(EVMC_CANCUN, eof) == evmone::EOFValidationError::success)
        (void)evmone::read_valid_eof1_header(eof);
    return 0;
}
