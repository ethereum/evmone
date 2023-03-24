# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# Integration tests for evmone-statetest.

set(PREFIX ${PREFIX}/statetest)
set(TESTS1 ${CMAKE_CURRENT_SOURCE_DIR}/tests1)
set(TESTS2 ${CMAKE_CURRENT_SOURCE_DIR}/tests2)
set(TESTS_EOF ${CMAKE_CURRENT_SOURCE_DIR}/eof)

add_test(
    NAME ${PREFIX}/no_arguments
    COMMAND evmone-statetest
)
set_tests_properties(
    ${PREFIX}/no_arguments PROPERTIES
    PASS_REGULAR_EXPRESSION "path is required"
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

add_test(
    NAME ${PREFIX}/single_file_list
    COMMAND evmone-statetest ${TESTS1}/SuiteA/test1.json --gtest_list_tests
)
set_tests_properties(
    ${PREFIX}/single_file_list PROPERTIES
    PASS_REGULAR_EXPRESSION [[
.*test/integration/statetest/tests1/SuiteA\.
  test1
]]
)

add_test(
    NAME ${PREFIX}/multiple_args_list
    COMMAND evmone-statetest ${TESTS1} ${TESTS2} ${TESTS1}/B/T.json ${TESTS1}/SuiteA --gtest_list_tests
)
set_tests_properties(
    ${PREFIX}/multiple_args_list PROPERTIES
    PASS_REGULAR_EXPRESSION [[
B\.
  T
SuiteA\.
  test1
  test2
  test1
.*test/integration/statetest/tests1/B\.
  T
\.
  test1
  test2
]]
)

add_test(
    NAME ${PREFIX}/invalid_path
    COMMAND evmone-statetest invalid.json
)
set_tests_properties(
    ${PREFIX}/invalid_path PROPERTIES
    PASS_REGULAR_EXPRESSION "path: Path does not exist: invalid\\.json"
)

add_test(
    NAME ${PREFIX}/trace
    COMMAND evmone-statetest ${TESTS1}/SuiteA/test1.json --trace
)
set_tests_properties(
    ${PREFIX}/trace PROPERTIES
    PASS_REGULAR_EXPRESSION [=[\{"pc":4,"op":1,"opName":"ADD","gas":0x5c872,"stack":\["0x1","0x1"\],"memorySize":0\}]=]
)

add_test(
    NAME ${PREFIX}/invalid_eof_in_state
    COMMAND evmone-statetest ${TESTS_EOF}/invalid_eof_in_state.json
)
set_tests_properties(
    ${PREFIX}/invalid_eof_in_state PROPERTIES
    PASS_REGULAR_EXPRESSION "EOF container at 0x0000000000000000000000000000000000bade0f is invalid"
)
