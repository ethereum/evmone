# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2024 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(FetchContent)

set(BUILD_SHARED_LIBS OFF)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON)
add_compile_options(-Wno-error)
FetchContent_Declare(
    libsecp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1
    GIT_TAG        v0.5.1
)

FetchContent_MakeAvailable(libsecp256k1)


add_executable(evmone-precompiles-bench)
target_compile_features(evmone-precompiles-bench PRIVATE cxx_std_20)
target_include_directories(evmone-precompiles-bench PRIVATE ..)
target_link_libraries(evmone-precompiles-bench PRIVATE evmone::state blst::blst benchmark::benchmark secp256k1)
target_sources(
    evmone-precompiles-bench PRIVATE
    bls_precompiles_bench.cpp
    precompiles_bench.cpp
)

add_test(NAME evmone/evmone-precompiles-bench COMMAND evmone-precompiles-bench --benchmark_min_time=1x)
set_tests_properties(evmone/evmone-precompiles-bench PROPERTIES FAIL_REGULAR_EXPRESSION "ERROR")
