# evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
# Copyright 2019 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0
include(ExternalProject)

include(FetchContent)

FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG v4.3.0
    GIT_SHALLOW TRUE
)
FetchContent_Declare(
    ut
    GIT_REPOSITORY https://github.com/boost-ext/ut.git
    GIT_TAG v2.1.1
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(glaze ut)

add_executable(evmone-fuzz-ut)
target_link_libraries(evmone-fuzz-ut PRIVATE evmone glaze::glaze ut)
target_sources(
    evmone-fuzz-ut PRIVATE
    fuzz_ut.cpp
)

get_target_property(type evmone TYPE)
if(NOT type STREQUAL STATIC_LIBRARY)
    message(FATAL_ERROR "The evmone must be built as static library")
endif()

add_executable(evmone-fuzzer fuzzer.cpp)
target_link_libraries(evmone-fuzzer PRIVATE evmone evmone::testutils evmc::mocked_host)

add_executable(evmone-fuzz)
target_link_libraries(evmone-fuzz PRIVATE evmone evmone::state glaze::glaze)
target_link_options(evmone-fuzz PRIVATE -fsanitize=fuzzer)
target_sources(
    evmone-fuzz PRIVATE
    fuzz.cpp
    fuzz_types.hpp
)
