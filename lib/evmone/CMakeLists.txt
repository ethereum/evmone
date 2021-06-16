# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019-2020 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(LibraryTools)

hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_library(evmone
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    baseline.cpp
    baseline.hpp
    baseline_instruction_table.cpp
    baseline_instruction_table.hpp
    execution.cpp
    execution.hpp
    instruction_traits.hpp
    instructions.cpp
    instructions.hpp
    instructions_calls.cpp
    limits.hpp
    opcodes_helpers.h
    tracing.cpp
    tracing.hpp
    vm.cpp
    vm.hpp
)
target_link_libraries(evmone PUBLIC evmc::evmc intx::intx PRIVATE evmc::instructions evmc::hex ethash::keccak)
target_include_directories(evmone PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
if(CABLE_COMPILER_GNULIKE)
    target_compile_options(evmone PRIVATE -fno-exceptions -fno-rtti)
endif()
set_target_properties(
    evmone
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_SOVERSION}
)

if(NOT SANITIZE)
    # On Linux, check if all symbols in evmone are resolved during linking.
    target_link_options(evmone PRIVATE $<$<PLATFORM_ID:Linux>:LINKER:--no-undefined>)
endif()

set_source_files_properties(vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)
