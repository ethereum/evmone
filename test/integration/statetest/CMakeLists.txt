# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# Integration tests for evmone-statetest.

set(PREFIX ${PREFIX}/statetest)
set(TESTS1 ${CMAKE_CURRENT_SOURCE_DIR}/tests1)

add_test(
    NAME ${PREFIX}/missing_arg
    COMMAND evmone-statetest
)
set_tests_properties(
    ${PREFIX}/missing_arg PROPERTIES
    PASS_REGULAR_EXPRESSION "Missing argument with the path to the tests directory"
)

add_test(
    NAME ${PREFIX}/tests1_list
    COMMAND evmone-statetest ${TESTS1} --gtest_list_tests
)
set_tests_properties(
    ${PREFIX}/tests1_list PROPERTIES
    PASS_REGULAR_EXPRESSION [[
B\.
  T
SuiteA\.
  test1
  test2
]]
)
