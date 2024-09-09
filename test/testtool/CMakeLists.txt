include(FetchContent)

FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG main
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_executable(e1test e1test.cpp)
target_link_libraries(e1test PRIVATE glaze::glaze)

