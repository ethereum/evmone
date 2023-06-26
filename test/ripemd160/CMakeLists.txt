
hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_executable(ripemd160-test)
target_link_libraries(ripemd160-test PRIVATE intx::intx evmc::evmc_cpp GTest::gtest_main)
target_sources(ripemd160-test PRIVATE ripemd160.cpp ripemd160.hpp ripemd160_test.cpp)
