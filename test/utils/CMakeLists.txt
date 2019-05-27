# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

add_library(testutils STATIC
    bytecode.hpp
    dump.cpp
    host_mock.hpp
    utils.cpp
    utils.hpp
)

target_link_libraries(testutils PRIVATE evmone evmc::instructions)
target_include_directories(testutils PUBLIC ${PROJECT_SOURCE_DIR} PRIVATE ${evmone_private_include_dir})
