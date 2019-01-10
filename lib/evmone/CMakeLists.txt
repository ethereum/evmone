# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

add_library(evmone
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    evmone.cpp
    execution.cpp
    execution.hpp
)
target_link_libraries(evmone PUBLIC intx::intx PRIVATE evmc::instructions ethash::ethash)
target_include_directories(evmone PUBLIC ${include_dir})
