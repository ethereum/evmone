# evmone: Ethereum Virtual Machine
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

cmake_minimum_required(VERSION 3.5)

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

cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Debug Release)
cable_configure_compiler(NO_PEDANTIC NO_CONVERSION_WARNINGS)

add_subdirectory(evmc)
add_subdirectory(lib)

if(EVMONE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

