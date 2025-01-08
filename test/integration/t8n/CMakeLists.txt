# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2024 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# Integration tests for evmone-t8n.

set(PREFIX ${PREFIX}/t8n)

set(TEST_CASE london_base_fee)

add_test(
    NAME ${PREFIX}/${TEST_CASE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/base_fee
    COMMAND
    evmone-t8n
    --state.fork London
    --state.reward 0
    --state.chainid 1
    --input.alloc alloc.json
    --input.txs txs.json
    --input.env env.json
    --output.basedir ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}
    --output.result out.json
)
set_tests_properties(${PREFIX}/${TEST_CASE} PROPERTIES FIXTURES_REQUIRED ${TEST_CASE})

add_test(
    NAME ${PREFIX}/${TEST_CASE}/out.json
    COMMAND ${CMAKE_COMMAND} -E cat ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}/out.json
)
string(
    JOIN ".*" EXPECTED_OUT
    # check computed base fee:
    [=["currentBaseFee": "0x8"]=]
)
set_tests_properties(
    ${PREFIX}/${TEST_CASE}/out.json PROPERTIES
    FIXTURES_CLEANUP ${TEST_CASE}
    PASS_REGULAR_EXPRESSION ${EXPECTED_OUT}
)


set(TEST_CASE berlin_base_fee)

add_test(
    NAME ${PREFIX}/${TEST_CASE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/base_fee
    COMMAND
    evmone-t8n
    --state.fork Berlin
    --state.reward 0
    --state.chainid 1
    --input.alloc alloc.json
    --input.txs txs.json
    --input.env env.json
    --output.basedir ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}
    --output.result out.json
)
set_tests_properties(${PREFIX}/${TEST_CASE} PROPERTIES FIXTURES_REQUIRED ${TEST_CASE})

add_test(
    NAME ${PREFIX}/${TEST_CASE}/out.json
    COMMAND ${CMAKE_COMMAND} -E cat ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}/out.json
)
set_tests_properties(
    ${PREFIX}/${TEST_CASE}/out.json PROPERTIES
    FIXTURES_CLEANUP ${TEST_CASE}
    # currentBaseFee should not be in the output before London:
    FAIL_REGULAR_EXPRESSION currentBaseFee
)


set(TEST_CASE cancun_create_tx)

add_test(
    NAME ${PREFIX}/${TEST_CASE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_CASE}
    COMMAND
    evmone-t8n
    --state.fork Cancun
    --state.reward 0
    --state.chainid 1
    --input.alloc alloc.json
    --input.txs txs.json
    --input.env env.json
    --output.basedir ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}
    --output.result out.json
    --output.alloc outAlloc.json
    --output.errorlog error.json
)
set_tests_properties(${PREFIX}/${TEST_CASE} PROPERTIES FIXTURES_REQUIRED ${TEST_CASE})

add_test(
    NAME ${PREFIX}/${TEST_CASE}/out.json
    COMMAND ${CMAKE_COMMAND} -E cat ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}/out.json
)
string(
    JOIN ".*" EXPECTED_OUT
    # Create blob transaction should be rejected:
    [=["error": "blob transaction must not be a create transaction"]=]
)
set_tests_properties(
    ${PREFIX}/${TEST_CASE}/out.json PROPERTIES
    FIXTURES_CLEANUP ${TEST_CASE}
    PASS_REGULAR_EXPRESSION ${EXPECTED_OUT}
)

add_test(
    NAME ${PREFIX}/${TEST_CASE}/outAlloc.json
    COMMAND ${CMAKE_COMMAND} -E cat ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}/outAlloc.json
)
string(
    JOIN ".*" EXPECTED_OUT_ALLOC
    # Beacon Roots system contract has new entry:
    [=["0x000f3df6d732807ef1319fb7b8bb8522d0beac02": .*"storage": \{[^}]*"0x00000000000000000000000000000000000000000000000000000000000016ca": "0x0000000000000000000000000000000000000000000000000000000054c99069"]=]
    # new account created with code 0x00:
    [=["0x6295ee1b4f6dd65047762f924ecd367c17eabf8f": \{[^}]*"code": "0x00",]=]
)
set_tests_properties(
    ${PREFIX}/${TEST_CASE}/outAlloc.json PROPERTIES
    FIXTURES_CLEANUP ${TEST_CASE}
    PASS_REGULAR_EXPRESSION ${EXPECTED_OUT_ALLOC}
)

set(TEST_CASE prague_empty_requests)

add_test(
    NAME ${PREFIX}/${TEST_CASE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_CASE}
    COMMAND
    evmone-t8n
    --state.fork Prague
    --state.reward 0
    --state.chainid 1
    --input.alloc alloc.json
    --input.txs txs.json
    --input.env env.json
    --output.basedir ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}
    --output.result out.json
)
set_tests_properties(${PREFIX}/${TEST_CASE} PROPERTIES FIXTURES_REQUIRED ${TEST_CASE})

add_test(
    NAME ${PREFIX}/${TEST_CASE}/out.json
    COMMAND ${CMAKE_COMMAND} -E cat ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CASE}/out.json
)
string(
    JOIN ".*" EXPECTED_OUT
    # empty requests list
    [=["requests": \[\]]=]
    # requests hash should be present
    [=["requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]=]
)
set_tests_properties(
    ${PREFIX}/${TEST_CASE}/out.json PROPERTIES
    FIXTURES_CLEANUP ${TEST_CASE}
    PASS_REGULAR_EXPRESSION ${EXPECTED_OUT}
)
