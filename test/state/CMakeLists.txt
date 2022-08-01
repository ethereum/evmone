# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state STATIC)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state PRIVATE evmone evmc::evmc_cpp ethash::keccak)
target_include_directories(evmone-state PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-state PRIVATE
    account.hpp
    hash_utils.hpp
    host.hpp
    host.cpp
    mpt.hpp
    mpt.cpp
    mpt_hash.hpp
    mpt_hash.cpp
    precompiles.hpp
    precompiles.cpp
    precompiles_cache.hpp
    precompiles_cache.cpp
    rlp.hpp
    state.hpp
    state.cpp
)

option(EVMONE_PRECOMPILES_SILKPRE "Enable precompiles support via silkpre library" OFF)
if(EVMONE_PRECOMPILES_SILKPRE)
    include(FetchContent)
    FetchContent_Declare(
        silkpre
        GIT_REPOSITORY https://github.com/torquem-ch/silkpre
        GIT_TAG 65a89f316ced2e25cbb455ae75eeed9e0bab8415
    )
    set(BUILD_SHARED_LIBS OFF)
    FetchContent_MakeAvailable(silkpre)
    set(DISABLE_WARNINGS -w)
    target_compile_options(silkpre PRIVATE ${DISABLE_WARNINGS})
    target_compile_options(secp256k1 PRIVATE ${DISABLE_WARNINGS})
    target_compile_options(ff PRIVATE ${DISABLE_WARNINGS})
    set_target_properties(silkpre secp256k1 ff PROPERTIES CXX_CLANG_TIDY "")

    target_link_libraries(evmone-state PRIVATE silkpre)
    target_compile_definitions(evmone-state PRIVATE EVMONE_PRECOMPILES_SILKPRE=1)
    target_sources(
        evmone-state PRIVATE
        precompiles_silkpre.hpp
        precompiles_silkpre.cpp
    )
endif()
