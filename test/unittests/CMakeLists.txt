# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018-2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

add_executable(evmone-unittests
    analysis_test.cpp
    bytecode_test.cpp
    evmone_test.cpp
    execution_test.cpp
    utils_test.cpp
)

target_link_libraries(evmone-unittests PRIVATE evmone testutils GTest::gtest GTest::main)
target_include_directories(evmone-unittests PRIVATE ${evmone_private_include_dir})

set_source_files_properties(evmone_test.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

gtest_add_tests(TARGET evmone-unittests TEST_PREFIX ${PROJECT_NAME}/unittests/)
