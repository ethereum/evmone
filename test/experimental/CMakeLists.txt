include(FetchContent)

FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/onqtam/doctest
    GIT_TAG        2.4.6
)

FetchContent_MakeAvailable(doctest)

add_executable(eof_validation eof_validation.cpp)
target_link_libraries(eof_validation PUBLIC evmc::hex doctest_with_main)
