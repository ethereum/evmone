# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

# The internal evmone unit tests. The generic EVM ones are also built in.
add_executable(evmone-unittests
    analysis_test.cpp
    bytecode_test.cpp
    evm_fixture.cpp
    evm_fixture.hpp
    evm_test.cpp
    evm_calls_test.cpp
    evm_eip2929_test.cpp
    evm_eip3198_basefee_test.cpp
    evm_state_test.cpp
    evm_other_test.cpp
    evmone_test.cpp
    execution_state_test.cpp
    op_table_test.cpp
    tracing_test.cpp
    utils_test.cpp
)
target_link_libraries(evmone-unittests PRIVATE evmone testutils evmc::instructions GTest::gtest GTest::gtest_main)
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
