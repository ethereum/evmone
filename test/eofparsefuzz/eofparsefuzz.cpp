// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/hex.hpp"
#include <evmone/eof.hpp>
#include <iostream>

using namespace evmone;

namespace
{
[[maybe_unused]] EOFValidationError to_header_validation_error(EOFValidationError err) noexcept
{
    using enum EOFValidationError;
    switch (err)
    {
    case no_terminating_instruction:
    case stack_underflow:
    case stack_overflow:
    case toplevel_container_truncated:  // ?
    case undefined_instruction:
    case invalid_max_stack_height:
        return success;
    default:
        return err;
    }
}
}  // namespace

extern "C" {
size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

size_t LLVMFuzzerCustomMutator(
    uint8_t* data_ptr, size_t data_size, size_t data_max_size, unsigned int seed)
{
    (void)seed;
    return LLVMFuzzerMutate(data_ptr, data_size, data_max_size);
}

int LLVMFuzzerTestOneInput(const uint8_t* data_ptr, size_t data_size) noexcept
{
    static constexpr auto rev = EVMC_PRAGUE;

    const bytes_view data{data_ptr, data_size};

    const auto vh = validate_header(rev, data);
    const auto v_status = validate_eof(rev, ContainerKind::runtime, data);
    assert(v_status != EOFValidationError::impossible);

    const auto p_vh_status = std::get_if<EOFValidationError>(&vh);
    assert(p_vh_status == nullptr || *p_vh_status != EOFValidationError::success);
    const auto vh_status = (p_vh_status != nullptr) ? *p_vh_status : EOFValidationError::success;
    assert(vh_status != EOFValidationError::impossible);

    if (v_status == EOFValidationError::success && vh_status != EOFValidationError::success)
        __builtin_trap();

    //    if (const auto expected = to_header_validation_error(v_status); vh_status != expected)
    //    {
    //        std::cerr << "vh_status: " << vh_status << "\nexpected:  " << expected
    //                  << "\neof: " << evmc::hex(data) << "\n";
    //        __builtin_trap();
    //    }

    if (v_status == EOFValidationError::success)
        (void)read_valid_eof1_header(data);
    return 0;
}
}
