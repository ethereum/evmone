# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

include(LibraryTools)

hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_library(evmone
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    evmone.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
)
target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx evmc::instructions ethash::keccak)
target_include_directories(evmone PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(NOT SANITIZE)
    # On Linux, check if all symbols in evmone are resolved during linking.
    target_link_options(evmone PRIVATE $<$<PLATFORM_ID:Linux>:LINKER:--no-undefined>)
endif()

set_source_files_properties(evmone.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)
