# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

include(GoogleTest)

set(evmone_private_include_dir ${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(utils)
add_subdirectory(bench)
add_subdirectory(unittests)

set_target_properties(
    evmone-bench evmone-unittests testutils PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
)

gtest_add_tests(
    TARGET evmc-vmtester
    SOURCES ${PROJECT_SOURCE_DIR}/evmc/test/vmtester/tests.cpp
    EXTRA_ARGS $<TARGET_FILE:evmone>
    TEST_PREFIX ${PROJECT_NAME}/evmc-vmtester/
)
