# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state STATIC)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state PUBLIC evmc::evmc_cpp PRIVATE evmone evmone::precompiles ethash::keccak)
target_include_directories(evmone-state PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-state PRIVATE
    account.hpp
    bloom_filter.hpp
    bloom_filter.cpp
    errors.hpp
    ethash_difficulty.hpp
    ethash_difficulty.cpp
    hash_utils.hpp
    hash_utils.cpp
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
        GIT_TAG 3322bb898ac9528fc2cf9a8df1e48360420d0c1a
        GIT_SHALLOW TRUE
    )
    set(BUILD_SHARED_LIBS_ORIG ${BUILD_SHARED_LIBS})
    set(BUILD_SHARED_LIBS OFF)
    FetchContent_MakeAvailable(silkpre)
    set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_ORIG})

    set_target_properties(
        silkpre secp256k1 ff
        PROPERTIES
        COMPILE_OPTIONS -w  # Disable warnings.
        CXX_CLANG_TIDY ""
    )

    target_link_libraries(evmone-state PRIVATE silkpre)
    target_compile_definitions(evmone-state PRIVATE EVMONE_PRECOMPILES_SILKPRE=1)
    target_sources(
        evmone-state PRIVATE
        precompiles_silkpre.hpp
        precompiles_silkpre.cpp
    )
endif()
