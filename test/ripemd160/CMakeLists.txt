
hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_executable(ripemd160-test)
target_compile_features(ripemd160-test PRIVATE cxx_std_20)
target_link_libraries(ripemd160-test PRIVATE intx::intx evmc::evmc_cpp GTest::gtest_main)
target_sources(ripemd160-test PRIVATE ripemd160.cpp ripemd160.hpp ripemd160_test.cpp)

add_executable(ripemd160-bench)
target_compile_features(ripemd160-bench PRIVATE cxx_std_20)
target_link_libraries(ripemd160-bench PRIVATE benchmark::benchmark)
target_sources(ripemd160-bench PRIVATE ripemd160.cpp ripemd160.hpp ripemd160_bench.cpp)
# BMI2 makes it slower
#target_compile_options(ripemd160-bench PRIVATE -mbmi2)
