// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <test/statetest/statetest.hpp>
#include <test/utils/utils.hpp>
#include <format>
#include <fstream>

namespace evmone::test
{
namespace
{
std::string_view get_tests_exception_name(EOFValidationError err) noexcept
{
    switch (err)
    {
    case EOFValidationError::success:
        return "None";
    case EOFValidationError::invalid_prefix:
        return "EOFException.INVALID_MAGIC";
    case EOFValidationError::eof_version_unknown:
        return "EOFException.INVALID_VERSION";
    case EOFValidationError::incomplete_section_size:
        return "EOFException.INCOMPLETE_SECTION_SIZE";
    case EOFValidationError::incomplete_section_number:
        return "EOFException.INCOMPLETE_SECTION_NUMBER";
    case EOFValidationError::header_terminator_missing:
        return "EOFException.MISSING_TERMINATOR";
    case EOFValidationError::type_section_missing:
        return "EOFException.MISSING_TYPE_HEADER";
    case EOFValidationError::code_section_missing:
        return "EOFException.MISSING_CODE_HEADER";
    case EOFValidationError::data_section_missing:
        return "EOFException.MISSING_DATA_SECTION";
    case EOFValidationError::zero_section_size:
        return "EOFException.ZERO_SECTION_SIZE";
    case EOFValidationError::section_headers_not_terminated:
        return "EOFException.MISSING_HEADERS_TERMINATOR";
    case EOFValidationError::invalid_section_bodies_size:
        return "EOFException.INVALID_SECTION_BODIES_SIZE";
    case EOFValidationError::unreachable_code_sections:
        return "EOFException.UNREACHABLE_CODE_SECTIONS";
    case EOFValidationError::undefined_instruction:
        return "EOFException.UNDEFINED_INSTRUCTION";
    case EOFValidationError::truncated_instruction:
        return "EOFException.TRUNCATED_INSTRUCTION";
    case EOFValidationError::invalid_rjump_destination:
        return "EOFException.INVALID_RJUMP_DESTINATION";
    case EOFValidationError::too_many_code_sections:
        return "EOFException.TOO_MANY_CODE_SECTIONS";
    case EOFValidationError::invalid_type_section_size:
        return "EOFException.INVALID_TYPE_SECTION_SIZE";
    case EOFValidationError::invalid_first_section_type:
        return "EOFException.INVALID_FIRST_SECTION_TYPE";
    case EOFValidationError::invalid_max_stack_height:
        return "EOFException.INVALID_MAX_STACK_HEIGHT";
    case EOFValidationError::max_stack_height_above_limit:
        return "EOFException.MAX_STACK_HEIGHT_ABOVE_LIMIT";
    case EOFValidationError::inputs_outputs_num_above_limit:
        return "EOFException.INPUTS_OUTPUTS_NUM_ABOVE_LIMIT";
    case EOFValidationError::no_terminating_instruction:
        return "EOFException.MISSING_STOP_OPCODE";
    case EOFValidationError::stack_height_mismatch:
        return "EOFException.INVALID_STACK_HEIGHT";
    case EOFValidationError::stack_higher_than_outputs_required:
        return "EOFException.STACK_HIGHER_THAN_OUTPUTS";
    case EOFValidationError::unreachable_instructions:
        return "EOFException.UNREACHABLE_INSTRUCTIONS";
    case EOFValidationError::stack_underflow:
        return "EOFException.STACK_UNDERFLOW";
    case EOFValidationError::stack_overflow:
        return "EOFException.STACK_OVERFLOW";  // TODO: STACK_OVERFLOW doesn't exist in eest
    case EOFValidationError::invalid_code_section_index:
        return "EOFException.INVALID_CODE_SECTION";
    case EOFValidationError::invalid_dataloadn_index:
        return "EOFException.INVALID_DATALOADN_INDEX";
    case EOFValidationError::jumpf_destination_incompatible_outputs:
        return "EOFException.JUMPF_DESTINATION_INCOMPATIBLE_OUTPUTS";
    case EOFValidationError::invalid_non_returning_flag:
        return "EOFException.INVALID_NON_RETURNING_FLAG";
    case EOFValidationError::callf_to_non_returning_function:
        return "EOFException.CALLF_TO_NON_RETURNING_FUNCTION";
    case EOFValidationError::too_many_container_sections:
        return "EOFException.TOO_MANY_CONTAINER_SECTIONS";
    case EOFValidationError::invalid_container_section_index:
        return "EOFException.INVALID_CONTAINER_SECTION_INDEX";
    case EOFValidationError::eofcreate_with_truncated_container:
        return "EOFException.EOF_CREATE_WITH_TRUNCATED_CONTAINER";
    case EOFValidationError::impossible:
        return "EOFException.UNDEFINED_EXCEPTION";
    }
    return "<unknown>";
}
}  // namespace

void eof_validation::TearDown()
{
    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        const auto& test_case = test_cases[i];
        EXPECT_EQ(evmone::validate_eof(rev, test_case.container), test_case.error)
            << "test case " << i << " " << test_case.name << "\n"
            << hex(test_case.container);
    }

    if (!export_file_path.empty())
        export_eof_validation_test();
}

void eof_validation::export_eof_validation_test()
{
    if (test_cases.empty())
        return;
    std::string pytest_params = "";
    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        const auto& test_case = test_cases[i];
        const auto case_name = test_case.name.empty() ?
                                   (std::string{export_test_name} + "_" + std::to_string(i)) :
                                   test_case.name;
        const auto case_number_ = std::to_string(i + 1);
        const auto case_number = std::string(5 - case_number_.size(), '0') + case_number_;

        std::string code_bytes = "";
        for (size_t z = 0; z < test_cases[i].container.size(); z++)
        {
            const auto byte = test_cases[i].container[z];
            const bytes_view byte_view{&byte, 1};
            code_bytes += std::string(24, ' ') + hex0x(byte_view) + ",\n";
        }
        const auto param = std::format(R"(pytest.param(
            Container(
                name="EOF1V{0}",
                raw_bytes=bytes(
                     [
{1}
                     ]),
            ),
            "{2}",
            {3},
            id="{4}",
        ),
        )",
            case_number, code_bytes, hex0x(test_cases[i].container),
            get_tests_exception_name(test_cases[i].error), case_name);
        pytest_params += param;
    }

    const auto python_test_code = std::format(R"("""
EOF v1 validation code
"""

import pytest
from ethereum_test_tools import EOFTestFiller
from ethereum_test_tools.eof.v1 import Container, EOFException

@pytest.mark.parametrize(
    "eof_code,expected_hex_bytecode,exception",
    [
        {}
    ]
)

def test_example_valid_invalid(
    eof_test: EOFTestFiller,
    eof_code: Container,
    expected_hex_bytecode: str,
    exception: EOFException | None,
):
    """
    Verify eof container construction and exception
    """
    if expected_hex_bytecode[0:2] == "0x":
        expected_hex_bytecode = expected_hex_bytecode[2:]
    assert bytes(eof_code) == bytes.fromhex(expected_hex_bytecode)

    eof_test(
        data=eof_code,
        expect_exception=exception,
    )
)",
        pytest_params);
    std::ofstream{export_file_path} << python_test_code;
}
}  // namespace evmone::test
