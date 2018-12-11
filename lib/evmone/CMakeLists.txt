# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

add_library(evmone
    analysis.cpp
    analysis.hpp
    execution.cpp
    execution.hpp
)
target_link_libraries(evmone PUBLIC intx::intx PRIVATE evmc::instructions)
