# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2025 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# Finds the GMP or MPIR library and its include directories.

find_library(GMP_LIBRARY NAMES gmp mpir DOC "GMP/MPIR library")
find_path(GMP_INCLUDE_DIR NAMES gmp.h DOC "GMP header")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    GMP
    REQUIRED_VARS GMP_LIBRARY GMP_INCLUDE_DIR
)

if(GMP_FOUND)
    if(NOT TARGET GMP::gmp)
        add_library(GMP::gmp UNKNOWN IMPORTED)
        set_target_properties(GMP::gmp PROPERTIES
            IMPORTED_LOCATION ${GMP_LIBRARY}
            IMPORTED_LINK_INTERFACE_LANGUAGES C
            INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
        )
    endif()
endif()
