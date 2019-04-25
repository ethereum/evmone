# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018-2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

add_executable(evmone-unittests
    test_analysis.cpp
    test_execution.cpp
    utils.cpp
    utils.hpp
)

target_link_libraries(evmone-unittests PRIVATE evmone evmc::instructions GTest::gtest GTest::main)
target_include_directories(evmone-unittests PRIVATE ${evmone_private_include_dir})
set_target_properties(evmone-unittests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ..)

gtest_add_tests(TARGET evmone-unittests TEST_PREFIX ${PROJECT_NAME}/unittests/)
