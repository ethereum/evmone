// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <test/statetest/statetest.hpp>
#include <fstream>

namespace evmone::test
{
namespace
{
std::string_view get_tests_error_message(EOFValidationError err) noexcept
{
    switch (err)
    {
    case EOFValidationError::success:
        return "success";
    case EOFValidationError::invalid_prefix:
        return "EOF_InvalidPrefix";
    case EOFValidationError::eof_version_unknown:
        return "EOF_UnknownVersion";
    case EOFValidationError::incomplete_section_size:
        return "EOF_IncompleteSectionSize";
    case EOFValidationError::incomplete_section_number:
        return "EOF_IncompleteSectionNumber";
    case EOFValidationError::header_terminator_missing:
        return "EOF_HeaderTerminatorMissing";
    case EOFValidationError::type_section_missing:
        return "EOF_TypeSectionMissing";
    case EOFValidationError::code_section_missing:
        return "EOF_CodeSectionMissing";
    case EOFValidationError::data_section_missing:
        return "EOF_DataSectionMissing";
    case EOFValidationError::zero_section_size:
        return "EOF_ZeroSectionSize";
    case EOFValidationError::section_headers_not_terminated:
        return "EOF_SectionHeadersNotTerminated";
    case EOFValidationError::invalid_section_bodies_size:
        return "EOF_InvalidSectionBodiesSize";
    case EOFValidationError::unreachable_code_sections:
        return "EOF_UnreachableCodeSections";
    case EOFValidationError::undefined_instruction:
        return "EOF_UndefinedInstruction";
    case EOFValidationError::truncated_instruction:
        return "EOF_TruncatedImmediate";
    case EOFValidationError::invalid_rjump_destination:
        return "EOF_InvalidJumpDestination";
    case EOFValidationError::too_many_code_sections:
        return "EOF_TooManyCodeSections";
    case EOFValidationError::invalid_type_section_size:
        return "EOF_InvalidTypeSectionSize";
    case EOFValidationError::invalid_first_section_type:
        return "EOF_InvalidFirstSectionType";
    case EOFValidationError::invalid_max_stack_height:
        return "EOF_InvalidMaxStackHeight";
    case EOFValidationError::max_stack_height_above_limit:
        return "EOF_MaxStackHeightExceeded";
    case EOFValidationError::inputs_outputs_num_above_limit:
        return "EOF_InputsOutputsNumAboveLimit";
    case EOFValidationError::no_terminating_instruction:
        return "EOF_InvalidCodeTermination";
    case EOFValidationError::stack_height_mismatch:
        return "EOF_ConflictingStackHeight";
    case EOFValidationError::stack_higher_than_outputs_required:
        return "EOF_InvalidNumberOfOutputs";
    case EOFValidationError::unreachable_instructions:
        return "EOF_UnreachableCode";
    case EOFValidationError::stack_underflow:
        return "EOF_StackUnderflow";
    case EOFValidationError::stack_overflow:
        return "EOF_StackOverflow";
    case EOFValidationError::invalid_code_section_index:
        return "EOF_InvalidCodeSectionIndex";
    case EOFValidationError::invalid_dataloadn_index:
        return "EOF_InvalidDataloadnIndex";
    case EOFValidationError::jumpf_destination_incompatible_outputs:
        return "EOF_JumpfDestinationIncompatibleOutputs";
    case EOFValidationError::invalid_non_returning_flag:
        return "EOF_InvalidNonReturningFlag";
    case EOFValidationError::callf_to_non_returning_function:
        return "EOF_CallfToNonReturningFunction";
    case EOFValidationError::too_many_container_sections:
        return "EOF_TooManyContainerSections";
    case EOFValidationError::invalid_container_section_index:
        return "EOF_InvalidContainerSectionIndex";
    case EOFValidationError::eofcreate_with_truncated_container:
        return "EOF_EofCreateWithTruncatedContainer";
    case EOFValidationError::impossible:
        return "impossible";
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
    json::json j;
    auto& jt = j[export_test_name];

    auto& jvectors = jt["vectors"];
    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        const auto& test_case = test_cases[i];
        const auto case_name = test_case.name.empty() ?
                                   (std::string{export_test_name} + "_" + std::to_string(i)) :
                                   test_case.name;

        auto& jcase = jvectors[case_name];
        jcase["code"] = hex0x(test_case.container);

        auto& jresults = jcase["results"][evmc::to_string(rev)];
        if (test_case.error == EOFValidationError::success)
            jresults["result"] = true;
        else
        {
            jresults["result"] = false;
            jresults["exception"] = get_tests_error_message(test_case.error);
        }
    }

    std::ofstream{export_file_path} << std::setw(2) << j;
}
}  // namespace evmone::test
