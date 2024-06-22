// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/hex.hpp"
#include <evmone/eof.hpp>
#include <iostream>

using namespace evmone;

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size) noexcept;


namespace
{
constexpr auto REV = EVMC_PRAGUE;

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

size_t mutate_part(
    const uint8_t* data, size_t data_size, size_t data_max_size, uint8_t* part, size_t part_size)
{
    const auto part_end = part + part_size;
    const auto size_available = data_max_size - data_size;
    const auto after_size = static_cast<size_t>((data + data_size - part_end));
    std::memmove(part_end + size_available, part_end, after_size);
    const auto part_new_size = LLVMFuzzerMutate(part, part_size, part_size + size_available);
    const auto part_new_end = part + part_new_size;
    std::memmove(part_new_end, part_end + size_available, after_size);
    const auto size_diff = part_new_size - part_size;
    return data_size + size_diff;
}

}  // namespace

extern "C" {

size_t LLVMFuzzerCustomMutator(
    uint8_t* data_ptr, size_t data_size, size_t data_max_size, unsigned int seed)
{
    (void)seed;

    const bytes_view data{data_ptr, data_size};

    const auto vh = validate_header(REV, data);
    if (std::holds_alternative<EOFValidationError>(vh))
        return LLVMFuzzerMutate(data_ptr, data_size, data_max_size);

    const auto& header = std::get<EOF1Header>(vh);
    const auto c_codes = header.code_sizes.size();
    const auto c_subcontainers = header.container_sizes.size();
    const auto c_all = c_codes + c_subcontainers + 2;
    const auto idx = seed % c_all;

    if (idx == 0)  // types
    {
        assert(!header.code_offsets.empty());
        const auto types_end = &data_ptr[header.code_offsets.front()];
        const auto types_size = c_codes * 4;
        const auto types_begin = types_end - types_size;
        return mutate_part(data_ptr, data_size, data_max_size, types_begin, types_size);
    }
    else if (idx == c_all - 1)  // data
    {
        const auto d_begin = &data_ptr[header.data_offset];
        const auto d_size = static_cast<size_t>((data_ptr + data_size - d_begin));
        return mutate_part(data_ptr, data_size, data_max_size, d_begin, d_size);
    }
    else if ()

    return LLVMFuzzerMutate(data_ptr, data_size, data_max_size);
}

int LLVMFuzzerTestOneInput(const uint8_t* data_ptr, size_t data_size) noexcept
{
    const bytes_view data{data_ptr, data_size};

    const auto vh = validate_header(REV, data);
    const auto v_status = validate_eof(REV, ContainerKind::runtime, data);
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
