# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(FetchContent)

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

option(EVMONE_PRECOMPILES_CKZG "Add c-kzg dependency for the pointEvaluation precompile")
if(EVMONE_PRECOMPILES_CKZG)
    FetchContent_Declare(
        C-KZG-4844
        GIT_REPOSITORY https://github.com/ethereum/c-kzg-4844
        GIT_TAG v0.3.1
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(C-KZG-4844)
    message(${c-kzg-4844_SOURCE_DIR})
    add_library(c_kzg_4844 STATIC ${c-kzg-4844_SOURCE_DIR}/src/c_kzg_4844.c)
    target_include_directories(c_kzg_4844 PUBLIC ${c-kzg-4844_SOURCE_DIR}/src ${c-kzg-4844_SOURCE_DIR}/blst/bindings)
    target_compile_definitions(c_kzg_4844 PUBLIC FIELD_ELEMENTS_PER_BLOB=4096)
    target_compile_options(c_kzg_4844 PRIVATE -Wno-error)
    target_link_libraries(c_kzg_4844 PRIVATE ${c-kzg-4844_SOURCE_DIR}/blst/libblst.a)

    target_link_libraries(evmone-state PRIVATE c_kzg_4844)
    target_compile_definitions(evmone-state PRIVATE EVMONE_PRECOMPILES_CKZG=1)
    target_sources(
        evmone-state PRIVATE
        precompiles_ckzg.hpp
        precompiles_ckzg.cpp
    )
endif()
