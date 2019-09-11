# evmone: Ethereum Virtual Machine
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

cmake_minimum_required(VERSION 3.13)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/evmc/.git)
    message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init")
endif()

option(BUILD_SHARED_LIBS "Build evmone as a shared library" ON)
option(EVMONE_TESTING "Build tests and test tools" OFF)

include(cmake/cable/bootstrap.cmake)
include(CableBuildType)
include(CableCompilerSettings)
include(CablePackage)
include(CableToolchains)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

cable_configure_toolchain(DEFAULT cxx17-pic)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

include(Hunter/init)

project(evmone LANGUAGES CXX)
set(PROJECT_VERSION 0.1.1)

hunter_add_package(ethash)
find_package(ethash CONFIG REQUIRED)

option(EVMC_TEST_TOOLS "Build EVMC test tools" ${EVMONE_TESTING})
add_subdirectory(evmc)

cable_configure_compiler(NO_PEDANTIC NO_CONVERSION_WARNINGS)
if(CABLE_COMPILER_GNULIKE)
    # Prepend to CXX flags to allow overriding.
    set(CMAKE_CXX_FLAGS "-fvisibility=hidden ${CMAKE_CXX_FLAGS}")
endif()

set(include_dir ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(lib)

if(EVMONE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()


install(TARGETS evmone EXPORT evmoneTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY ${include_dir}/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

cable_add_archive_package()
