# evmone: Ethereum Virtual Machine
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

cmake_minimum_required(VERSION 3.5)

option(BUILD_SHARED_LIBS "Build evmone as a shared library" ON)
option(EVMONE_TESTING "Build tests and test tools" OFF)

include(cmake/cable/bootstrap.cmake)
include(CableBuildType)
include(CableCompilerSettings)
include(CableToolchains)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

cable_configure_toolchain(DEFAULT cxx17-pic)

if(EVMONE_TESTING)
    include(HunterConfig)
endif()

project(evmone)
set(PROJECT_VERSION 0.1.0-dev)

option(INTX_TESTING "Build intx with tests" OFF)
add_subdirectory(intx)

option(EVMC_TESTING "Build EVMC tests and test tools" ${EVMONE_TESTING})
add_subdirectory(evmc)

cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Debug Release)
cable_configure_compiler(NO_PEDANTIC NO_CONVERSION_WARNINGS)

set(include_dir ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(lib)

if(EVMONE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

