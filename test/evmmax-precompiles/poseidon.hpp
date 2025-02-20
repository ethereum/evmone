#pragma once

#include <test/utils/bytecode.hpp>

evmone::test::bytecode create_poseidon_hash_bytecode();
evmone::test::bytecode create_poseidon_hash_bytecode_datacopy();
evmone::test::bytecode create_poseidon_hash_bytecode_vectorized();
evmone::test::bytecode create_poseidon_hash_bytecode_vectorized_datacopy();
