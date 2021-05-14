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

    get_property(ALL_TESTS DIRECTORY PROPERTY TESTS)
    set_tests_properties("${ALL_TESTS}" PROPERTIES ENVIRONMENT LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/integration-%p.profraw)
endif()
