# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2024 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

set(PREFIX ${PROJECT_NAME}/integration/eofparse)

string(REPLACE ";" " " CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")

add_test(NAME ${PREFIX}/minimal_eof COMMAND sh -c "echo EF0001.010004 0200010001 FF0000 00,00800000 FE | ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse>")
set_tests_properties(${PREFIX}/minimal_eof PROPERTIES PASS_REGULAR_EXPRESSION "OK fe")

add_test(NAME ${PREFIX}/two_code_sections COMMAND sh -c "echo EF0001 010008 02000200030001 FF0000 00 00800000,00800000 E50001,00 | ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse>")
set_tests_properties(${PREFIX}/two_code_sections PROPERTIES PASS_REGULAR_EXPRESSION "OK e50001,00")

add_test(NAME ${PREFIX}/eof_version_unknown COMMAND sh -c "echo EF00.FF | ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse>")
set_tests_properties(${PREFIX}/eof_version_unknown PROPERTIES PASS_REGULAR_EXPRESSION "err: eof_version_unknown")

add_test(NAME ${PREFIX}/invalid_hex COMMAND sh -c "echo gaga | ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse>")
set_tests_properties(${PREFIX}/invalid_hex PROPERTIES PASS_REGULAR_EXPRESSION "err: invalid hex")

add_test(NAME ${PREFIX}/example_input_file COMMAND sh -c "${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse> <${CMAKE_CURRENT_SOURCE_DIR}/two_errors.txt")
set_tests_properties(${PREFIX}/example_input_file PROPERTIES PASS_REGULAR_EXPRESSION "OK 00\nerr: type_section_missing\nerr: no_terminating_instruction")

add_test(NAME ${PREFIX}/exit_code COMMAND sh -c "${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:evmone-eofparse> <${CMAKE_CURRENT_SOURCE_DIR}/two_errors.txt >/dev/null; echo $?")
set_tests_properties(${PREFIX}/exit_code PROPERTIES PASS_REGULAR_EXPRESSION "2")
