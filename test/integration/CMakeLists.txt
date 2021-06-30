# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2021 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

set(PREFIX ${PROJECT_NAME}/integration)

get_target_property(EVMONE_LIB_TYPE evmone TYPE)
if(EVMONE_LIB_TYPE STREQUAL SHARED_LIBRARY)

    add_test(NAME ${PREFIX}/histogram COMMAND $<TARGET_FILE:evmc::tool> --vm $<TARGET_FILE:evmone>,O=0,histogram run 6000808080800101010200)
    set_tests_properties(
        ${PREFIX}/histogram PROPERTIES PASS_REGULAR_EXPRESSION
        "--- # HISTOGRAM depth=0
opcode,count
STOP,1
ADD,3
MUL,1
PUSH1,1
DUP1,4
")

    add_test(NAME ${PREFIX}/trace COMMAND $<TARGET_FILE:evmc::tool> --vm $<TARGET_FILE:evmone>,O=0,trace run 60006002800103)
    set_tests_properties(
        ${PREFIX}/trace PROPERTIES PASS_REGULAR_EXPRESSION
        "{\"depth\":0,\"rev\":\"London\",\"static\":false}
{\"pc\":0,\"op\":96,\"opName\":\"PUSH1\",\"gas\":1000000,\"stack\":\\[\\],\"memorySize\":0}
{\"pc\":2,\"op\":96,\"opName\":\"PUSH1\",\"gas\":999997,\"stack\":\\[\"0x0\"\\],\"memorySize\":0}
{\"pc\":4,\"op\":128,\"opName\":\"DUP1\",\"gas\":999994,\"stack\":\\[\"0x0\",\"0x2\"\\],\"memorySize\":0}
{\"pc\":5,\"op\":1,\"opName\":\"ADD\",\"gas\":999991,\"stack\":\\[\"0x0\",\"0x2\",\"0x2\"\\],\"memorySize\":0}
{\"pc\":6,\"op\":3,\"opName\":\"SUB\",\"gas\":999988,\"stack\":\\[\"0x0\",\"0x4\"\\],\"memorySize\":0}
{\"error\":null,\"gas\":999985,\"gasUsed\":15,\"output\":\"\"}
")


    get_property(ALL_TESTS DIRECTORY PROPERTY TESTS)
    set_tests_properties(${ALL_TESTS} PROPERTIES ENVIRONMENT LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/integration-%p.profraw)
endif()
