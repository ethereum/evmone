# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

include(LibraryTools)

add_library(evmone
    ${include_dir}/evmone/evmone.h
    advanced_analysis.cpp
    advanced_analysis.hpp
    advanced_execution.cpp
    advanced_execution.hpp
    advanced_instructions.cpp
    baseline.cpp
    baseline.hpp
    baseline_instruction_table.cpp
    baseline_instruction_table.hpp
    eof.cpp
    eof.hpp
    instructions.hpp
    instructions_calls.cpp
    instructions_opcodes.hpp
    instructions_storage.cpp
    instructions_traits.hpp
    instructions_xmacro.hpp
    opcodes_helpers.h
    tracing.cpp
    tracing.hpp
    vm.cpp
    vm.hpp
)
target_compile_features(evmone PUBLIC cxx_std_20)
target_link_libraries(evmone PUBLIC evmc::evmc intx::intx PRIVATE ethash::keccak crypto3::hash)
target_include_directories(evmone PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(EVMONE_X86_64_ARCH_LEVEL GREATER_EQUAL 2)
    # Add CPU architecture runtime check. The EVMONE_X86_64_ARCH_LEVEL has a valid value.
    target_sources(evmone PRIVATE cpu_check.cpp)
    set_source_files_properties(cpu_check.cpp PROPERTIES COMPILE_DEFINITIONS EVMONE_X86_64_ARCH_LEVEL=${EVMONE_X86_64_ARCH_LEVEL})
endif()

if(CABLE_COMPILER_GNULIKE)
    target_compile_options(
        evmone PRIVATE
        -fno-exceptions
        $<$<CXX_COMPILER_ID:GNU>:-Wstack-usage=2800>
    )
    if(NOT SANITIZE MATCHES undefined)
        # RTTI can be disabled except for UBSan which checks vptr integrity.
        target_compile_options(evmone PRIVATE -fno-rtti)
    endif()
endif()
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

set_source_files_properties(vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)

function(add_circuit name)
    set(prefix ARG)
    set(noValues "")
    set(singleValues)
    set(multiValues SOURCES INCLUDE_DIRECTORIES LINK_LIBRARIES COMPILER_OPTIONS)
    cmake_parse_arguments(${prefix}
                          "${noValues}"
                          "${singleValues}"
                          "${multiValues}"
                          ${ARGN})

    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "SOURCES for ${name} circuit was not defined")
    endif()

    foreach(source ${ARG_SOURCES})
        if(NOT IS_ABSOLUTE ${source})
            list(APPEND CIRCUIT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        else()
            list(APPEND CIRCUIT_SOURCES "${source}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES CIRCUIT_SOURCES)

    foreach(ITR ${CIRCUIT_SOURCES})
        if(NOT EXISTS ${ITR})
            message(SEND_ERROR "Cannot find circuit source file: ##${ITR}##")
        endif()
    endforeach()

    set(INCLUDE_DIRS_LIST "")
    # Collect include directories from dependencies first
    foreach(lib ${ARG_LINK_LIBRARIES})
        get_target_property(lib_include_dirs ${lib} INTERFACE_INCLUDE_DIRECTORIES)
        foreach(dir ${lib_include_dirs})
            if (dir MATCHES ".*/.*")
                list(APPEND INCLUDE_DIRS_LIST "-I${dir}")
                message(STATUS "${lib}: -I${dir}")
            endif()
        endforeach()
    endforeach()
    # Add passed include directories
    foreach(include_dir ${ARG_INCLUDE_DIRECTORIES})
        if(NOT IS_ABSOLUTE ${include_dir})
            set(include_dir "${CMAKE_CURRENT_SOURCE_DIR}/${include_dir}")
        endif()
        list(APPEND INCLUDE_DIRS_LIST "-I${include_dir}")
    endforeach()
    if (NOT ZKLLVM_SOURCE_ROOT OR NOT ZKLLVM_BINARY_ROOT)
        message(FATAL_ERROR "ZKLLVM_SOURCE_ROOT and ZKLLVM_BINARY_ROOT must be set")
    endif()
    list(APPEND INCLUDE_DIRS_LIST -I${ZKLLVM_SOURCE_ROOT}/libs/stdlib/libcpp -I${ZKLLVM_SOURCE_ROOT}/libs/circifier/clang/lib/Headers -I${ZKLLVM_SOURCE_ROOT}/libs/stdlib/libc/include)
    list(REMOVE_DUPLICATES INCLUDE_DIRS_LIST)

    set(CLANG ${ZKLLVM_BINARY_ROOT}/libs/circifier/llvm/bin/clang)
    set(LINKER ${ZKLLVM_BINARY_ROOT}/libs/circifier/llvm/bin/llvm-link)

    # Compile sources
    set(compiler_outputs "")
    add_custom_target(${name}_compile_sources)
    foreach(source ${CIRCUIT_SOURCES})
        get_filename_component(source_base_name ${source} NAME)
        add_custom_target(${name}_${source_base_name}_ll
                        COMMAND ${CLANG} -target assigner -Xclang -fpreserve-vec3-type -Werror=unknown-attributes -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION
                        -D__ZKLLVM__
                        ${INCLUDE_DIRS_LIST} -emit-llvm -O1 -S ${ARG_COMPILER_OPTIONS}  -o ${name}_${source_base_name}.ll ${source}

                        VERBATIM COMMAND_EXPAND_LISTS

                        SOURCES ${source})
        add_dependencies(${name}_compile_sources ${name}_${source_base_name}_ll)
        list(APPEND compiler_outputs "${name}_${source_base_name}.ll")
    endforeach()

    list(APPEND compiler_outputs ${ZKLLVM_BINARY_ROOT}/libs/stdlib/libcpp/zkllvm-libcpp.ll ${ZKLLVM_BINARY_ROOT}/libs/stdlib/libc/zkllvm-libc.ll)

    # Link sources
    add_custom_target(${name}
                      COMMAND ${LINKER} -S -o ${name}.ll ${compiler_outputs}
                      DEPENDS ${name}_compile_sources
                      VERBATIM COMMAND_EXPAND_LISTS)
    set_target_properties(${name} PROPERTIES OUTPUT_NAME ${name}.ll)
endfunction(add_circuit)

add_circuit(evmone_circuit SOURCES
    advanced_analysis.cpp
    advanced_execution.cpp
    advanced_instructions.cpp
    baseline.cpp
    baseline_instruction_table.cpp
    eof.cpp
    instructions_calls.cpp
    instructions_storage.cpp
    tracing.cpp
    vm.cpp
    LINK_LIBRARIES evmc::evmc intx::intx ethash::keccak crypto3::hash
    INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/include
    COMPILER_OPTIONS -std=c++20 -DPROJECT_VERSION="dev" -DBOOST_ARCH_CURRENT_WORD_BITS=64
)
