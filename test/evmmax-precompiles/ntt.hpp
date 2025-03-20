#pragma once

#include <test/utils/bytecode.hpp>

evmone::test::bytecode create_nttfw_bytecode();
evmone::test::bytecode create_shuffle_bytecode_test(size_t input_size, uint8_t window_size);
evmone::test::bytecode create_spread_bytecode_test(size_t input_size, uint8_t window_size);
