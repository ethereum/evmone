# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

add_library(testutils STATIC
    bytecode.hpp
    host_mock.hpp
    utils.cpp
    utils.hpp
)

target_link_libraries(testutils PRIVATE evmc::instructions)
target_include_directories(testutils PUBLIC ${PROJECT_SOURCE_DIR})

add_library(testutils-dump STATIC dump.cpp)
target_link_libraries(testutils-dump PRIVATE testutils evmone)
target_include_directories(testutils-dump PRIVATE ${evmone_private_include_dir})
