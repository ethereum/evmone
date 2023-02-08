# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(evmone-t8n)
target_link_libraries(evmone-t8n PRIVATE evmone::statetestutils nlohmann_json::nlohmann_json)
target_link_libraries(evmone-t8n PRIVATE evmc::evmc evmone)
target_sources(evmone-t8n PRIVATE t8n.cpp)

# Provide the project version to selected source files.
set_source_files_properties(
        t8n.cpp
        PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}"
)