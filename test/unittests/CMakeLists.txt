# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# The internal evmone unit tests. The generic EVM ones are also built in.
add_executable(evmone-unittests)
target_sources(
    evmone-unittests PRIVATE
    analysis_test.cpp
    bytecode_test.cpp
    eof_test.cpp
    eof_validation_test.cpp
    evm_fixture.cpp
    evm_fixture.hpp
    evm_test.cpp
    evm_calls_test.cpp
    evm_control_flow_test.cpp
    evm_eip663_dupn_swapn_test.cpp
    evm_eip2929_test.cpp
    evm_eip3198_basefee_test.cpp
    evm_eip3855_push0_test.cpp
    evm_eip3860_initcode_test.cpp
    evm_eof_test.cpp
    evm_eof_function_test.cpp
    evm_eof_rjump_test.cpp
    evm_memory_test.cpp
    evm_state_test.cpp
    evm_storage_test.cpp
    evm_other_test.cpp
    evm_benchmark_test.cpp
    evmone_test.cpp
    execution_state_test.cpp
    instructions_test.cpp
    state_bloom_filter_test.cpp
    state_mpt_hash_test.cpp
    state_mpt_test.cpp
    state_new_account_address_test.cpp
    state_rlp_test.cpp
    state_transition.hpp
    state_transition.cpp
    state_transition_block_test.cpp
    state_transition_create_test.cpp
    state_transition_eof_test.cpp
    statetest_loader_block_info_test.cpp
    statetest_loader_test.cpp
    statetest_loader_tx_test.cpp
    statetest_logs_hash_test.cpp
    tracing_test.cpp
)
target_link_libraries(evmone-unittests PRIVATE evmone evmone::state evmone::statetestutils testutils evmc::instructions GTest::gtest GTest::gtest_main)
target_include_directories(evmone-unittests PRIVATE ${evmone_private_include_dir})

gtest_discover_tests(evmone-unittests TEST_PREFIX ${PROJECT_NAME}/unittests/)

option(EVMONE_EVM_TEST_TOOL "Enable EVM unit testing tool for EVMC implementations (not maintained)" OFF)
if(EVMONE_EVM_TEST_TOOL)
    # The evm-test tool that contains the all evm-unittests and loads VMs as EVMC modules.
    add_executable(evm-test main.cpp)
    target_link_libraries(evm-test PRIVATE evm-unittests testutils evmc::evmc evmc::loader GTest::gtest)
endif()

# Provide the project version to selected source files.
set_source_files_properties(
    evmone_test.cpp
    main.cpp
    PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}"
)
