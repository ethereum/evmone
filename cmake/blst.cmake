include_guard()
include(ExternalProject)

if(MSVC)
    set(BLST_BUILD_SCRIPT build.bat)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Don't pass CC to the script because it doesn't work.
    set(BLST_BUILD_SCRIPT ./build.sh -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
else()
    # Pass CC and AR, this supports cross-compilation.
    # Pass CFLAGS as part of CC (e.g. to pass -m32). Using CFLAGS directly overwrites blst's default.
    string(JOIN " " BLST_CC ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS})
    set(BLST_BUILD_SCRIPT ./build.sh CC='${BLST_CC}' AR='${CMAKE_AR}')
endif()

ExternalProject_Add(
    blst
    EXCLUDE_FROM_ALL TRUE
    PREFIX ${PROJECT_BINARY_DIR}/deps
    URL https://github.com/supranational/blst/archive/refs/tags/v0.3.13.tar.gz
    URL_HASH SHA256=89772cef338e93bc0348ae531462752906e8fa34738e38035308a7931dd2948f
    DOWNLOAD_NO_PROGRESS TRUE
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${BLST_BUILD_SCRIPT}
    BUILD_IN_SOURCE TRUE
    BUILD_BYPRODUCTS "<SOURCE_DIR>/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX}"
    LOG_BUILD TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
    INSTALL_COMMAND ""
)
ExternalProject_Get_Property(blst SOURCE_DIR)

set(BLST_INCLUDE_DIR ${SOURCE_DIR}/bindings)
file(MAKE_DIRECTORY ${BLST_INCLUDE_DIR})

add_library(blst::blst STATIC IMPORTED GLOBAL)
add_dependencies(blst::blst blst)
set_target_properties(
    blst::blst PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_INCLUDE_DIR}
    IMPORTED_LOCATION ${SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}blst${CMAKE_STATIC_LIBRARY_SUFFIX}
)

