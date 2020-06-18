# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

include(FetchContent)
include(LibraryTools)

set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
    intx
    URL https://github.com/chfast/intx/archive/9846d5f1ffa2e919115bb25fdf17dd237712c3a9.tar.gz
    URL_HASH SHA256=ec5c1adf32aef849d45e4687e9339b2f310a832ccc9f34ee2b025288110e49f2
    DOWNLOAD_DIR ${CMAKE_SOURCE_DIR}/deps/download
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/deps/intx
)
FetchContent_MakeAvailable(intx)

#hunter_add_package(intx)
#find_package(intx CONFIG REQUIRED)

add_library(evmone
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    evmone.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
    limits.hpp
    opcodes_helpers.h
)
target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak)
target_include_directories(evmone PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
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

set_source_files_properties(evmone.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)
