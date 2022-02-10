# Cable: CMake Bootstrap Library <https://github.com/ethereum/cable>
# Copyright 2018-2020 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

# Cable Compiler Settings, version 1.0.1
#
# This CMake module provides default configuration (with some options)
# for C/C++ compilers. Use cable_configure_compiler().
#
# CHANGELOG
#
# 1.0.1 - 2020-01-30
# - Do not explicitly set -mtune=generic, this is default anyway.
#
# 1.0.0 - 2019-12-20

if(cable_compiler_settings_included)
    return()
endif()
set(cable_compiler_settings_included TRUE)

include(CheckCXXCompilerFlag)

# Adds CXX compiler flag if the flag is supported by the compiler.
#
# This is effectively a combination of CMake's check_cxx_compiler_flag()
# and add_compile_options():
#
#    if(check_cxx_compiler_flag(flag))
#        add_compile_options(flag)
#
function(cable_add_cxx_compiler_flag_if_supported FLAG)
    # Remove leading - or / from the flag name.
    string(REGEX REPLACE "^-|/" "" name ${FLAG})
    check_cxx_compiler_flag(${FLAG} ${name})
    if(${name})
        add_compile_options(${FLAG})
    endif()

    # If the optional argument passed, store the result there.
    if(ARGV1)
        set(${ARGV1} ${name} PARENT_SCOPE)
    endif()
endfunction()


# Configures the compiler with default flags.
macro(cable_configure_compiler)
    if(NOT PROJECT_SOURCE_DIR)
        message(FATAL_ERROR "cable_configure_compiler() must be used after project()")
    endif()

    # Determine if this is the main or a subproject. Leave this variable available for later use.
    if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
        set(PROJECT_IS_MAIN TRUE)
    else()
        set(PROJECT_IS_MAIN FALSE)
    endif()

    if(PROJECT_IS_MAIN)
        # Do this configuration only in the main project.

        cmake_parse_arguments(cable "NO_CONVERSION_WARNINGS;NO_STACK_PROTECTION;NO_PEDANTIC" "" "" ${ARGN})

        if(cable_UNPARSED_ARGUMENTS)
            message(FATAL_ERROR "cable_configure_compiler: Unknown options: ${cable_UNPARSED_ARGUMENTS}")
        endif()

        # Set helper variables recognizing C++ compilers.
        if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
            set(CABLE_COMPILER_GNU TRUE)
        elseif(${CMAKE_CXX_COMPILER_ID} MATCHES Clang)
            # This matches both clang and AppleClang.
            set(CABLE_COMPILER_CLANG TRUE)
        endif()

        if(CABLE_COMPILER_GNU OR CABLE_COMPILER_CLANG)
            set(CABLE_COMPILER_GNULIKE TRUE)
        endif()

        if(CABLE_COMPILER_GNULIKE)

            if(NOT cable_NO_PEDANTIC)
                add_compile_options(-Wpedantic)
            endif()

            # Enable basing warnings set and treat them as errors.
            add_compile_options(-Werror -Wall -Wextra -Wshadow)

            if(NOT cable_NO_CONVERSION_WARNINGS)
                # Enable conversion warnings if not explicitly disabled.
                add_compile_options(-Wconversion -Wsign-conversion)
            endif()

            # Allow unknown pragmas, we don't want to wrap them with #ifdefs.
            add_compile_options(-Wno-unknown-pragmas)

            # Stack protection.
            check_cxx_compiler_flag(-fstack-protector fstack-protector)
            if(fstack-protector)
                # The compiler supports stack protection options.
                if(cable_NO_STACK_PROTECTION)
                    # Stack protection explicitly disabled.
                    # Add "no" flag, because in some configuration the compiler has it enabled by default.
                    add_compile_options(-fno-stack-protector)
                else()
                    # Try enabling the "strong" variant.
                    cable_add_cxx_compiler_flag_if_supported(-fstack-protector-strong have_stack_protector_strong_support)
                    if(NOT have_stack_protector_strong_support)
                        # Fallback to standard variant if "strong" not available.
                        add_compile_options(-fstack-protector)
                    endif()
                endif()
            endif()

            cable_add_cxx_compiler_flag_if_supported(-Wimplicit-fallthrough)

        elseif(MSVC)

            # Get rid of default warning level.
            string(REPLACE " /W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
            string(REPLACE " /W3" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

            # Enable basing warnings set and treat them as errors.
            add_compile_options(/W4 /WX)

            # Allow unknown pragmas, we don't want to wrap them with #ifdefs.
            add_compile_options(/wd4068)

        endif()

        # Option for arch=native.
        option(NATIVE "Build for native CPU" OFF)
        if(NATIVE)
            if(MSVC)
                add_compile_options(-arch:AVX)
            else()
                add_compile_options(-mtune=native -march=native)
            endif()
        endif()

        # Sanitizers support.
        set(SANITIZE OFF CACHE STRING "Build with the specified sanitizer")
        if(SANITIZE)
            # Set the linker flags first, they are required to properly test the compiler flag.
            set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=${SANITIZE} ${CMAKE_SHARED_LINKER_FLAGS}")
            set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=${SANITIZE} ${CMAKE_EXE_LINKER_FLAGS}")

            set(test_name have_fsanitize_${SANITIZE})
            check_cxx_compiler_flag(-fsanitize=${SANITIZE} ${test_name})
            if(NOT ${test_name})
                message(FATAL_ERROR "Unsupported sanitizer: ${SANITIZE}")
            endif()
            add_compile_options(-fno-omit-frame-pointer -fsanitize=${SANITIZE})

            set(blacklist_file ${PROJECT_SOURCE_DIR}/sanitizer-blacklist.txt)
            if(EXISTS ${blacklist_file})
                cable_add_cxx_compiler_flag_if_supported(-fsanitize-blacklist=${blacklist_file})
            endif()
            unset(blacklist_file)
        endif()

        # The "Coverage" build type.
        if(CABLE_COMPILER_CLANG)
            set(CMAKE_CXX_FLAGS_COVERAGE "-fprofile-instr-generate -fcoverage-mapping")
        elseif(CABLE_COMPILER_GNU)
            set(CMAKE_CXX_FLAGS_COVERAGE "--coverage")
        endif()
    endif()
endmacro()
