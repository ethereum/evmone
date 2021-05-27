add_executable(evmone-tool)
target_sources(evmone-tool PRIVATE evmone_cmd.cpp)
target_link_libraries(evmone-tool PRIVATE evmone evmc::hex)
target_compile_options(evmone-tool PUBLIC -fno-exceptions)
