#!/usr/bin/env -S cmake -P

# Cable: CMake Bootstrap Library <https://github.com/ethereum/cable>
# Copyright 2019-2020 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

# The cable command-line tool, version 1.0.0
#
# This CMake script allows installing or updating Cable modules.
# Commands:
# - list
# - install
# - update
#
# You can also include it from CMakeLists.txt to add Cable modules to
# CMAKE_MODULE_PATH.

if(NOT CMAKE_SCRIPT_MODE_FILE)
    # Setup Cable modules when included as include(cable.cmake).
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})
    return()
endif()

set(repo_url https://github.com/ethereum/cable)
set(download_url ${repo_url}/raw/master)
set(cable_dir ${CMAKE_CURRENT_LIST_DIR})

function(get_modules_list OUTPUT_LIST)
    file(GLOB modules_files RELATIVE ${cable_dir} "${cable_dir}/Cable*.cmake")
    string(REPLACE ".cmake" "" modules "${modules_files}")
    set(${OUTPUT_LIST} "${modules}" PARENT_SCOPE)
endfunction()

function(download MODULE_NAME)
    set(module_file ${MODULE_NAME}.cmake)
    set(src "${download_url}/${module_file}")
    set(dst "${cable_dir}/${module_file}")
    file(DOWNLOAD "${src}" "${dst}" STATUS status)
    list(GET status 0 status_code)
    list(GET status 1 error_msg)
    if(status EQUAL 0)
        set(msg DONE)
    else()
        file(REMOVE "${dst}")
        set(msg "${status_code} ${error_msg}\n  ${src}")
    endif()
    message("Downloading ${MODULE_NAME}: ${msg}")
endfunction()

set(cmd ${CMAKE_ARGV3})  # cmake -P cable.cmake ARGV3 ARGV4 ...
if(NOT cmd)
    set(cmd list)
endif()

if(cmd STREQUAL list)
    get_modules_list(modules)
    string(REPLACE ";" "\n  " modules "${modules}")
    message("Installed modules:\n  ${modules}")
elseif(cmd STREQUAL update)
    get_modules_list(modules)
    foreach(module ${modules})
        download(${module})
    endforeach()
elseif(cmd STREQUAL install)
    download(${CMAKE_ARGV4})
else()
    message(FATAL_ERROR "Unknown command '${cmd}'")
endif()
