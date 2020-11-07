// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

/// This file contains unit tests for EVM384 prototype.
#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, addmod384_1)
{
    rev = EVMC_ISTANBUL;
    const auto indices_packed = push("00000000000000000000003000000060");  // 0,0,48,96

    const auto code = calldatacopy(0, 0, OP_CALLDATASIZE) + indices_packed + "c0" + ret(0, 48);
    execute(code,
        // clang-format off
        "3c119b3934156e9d9a495378725bb6c7fdcd12784743919063f5a383d2d2af117e025fdb0fb03fa723a62a4d6d968d2b"
        "f1562b8a749c87046d34a6d1101226508bb99a91982faeac365505dc7d9366404d9808a02531e3e80c82cdbab995821e"
        "ec1e91ae1c738c60602becdaa2c68049efc48e8efa17054cdfb487bd3ccf137fe7e517dbee90eef07123d231ea794fa5"
        // clang-format on
    );
    EXPECT_GAS_USED(EVMC_SUCCESS, 58);
    EXPECT_EQ(hex(bytes_view(result.output_data, result.output_size)),
        "2d68c6c3a8b1f5a1077ef949836ddc178987ad09e0723f3d9a4aa95f50661652cb9a677b35e122903028f80727"
        "2c104a");
}

TEST_P(evm, submod384_1)
{
    rev = EVMC_ISTANBUL;
    const auto indices_packed = push("00000000000000000000003000000060");  // 0,0,48,96

    const auto code = calldatacopy(0, 0, OP_CALLDATASIZE) + indices_packed + "c1" + ret(0, 48);
    execute(code,
        // clang-format off
       "2d68c6c3a8b1f5a1077ef949836ddc178987ad09e0723f3d9a4aa95f50661652cb9a677b35e122903028f807272c104a"
       "f1562b8a749c87046d34a6d1101226508bb99a91982faeac365505dc7d9366404d9808a02531e3e80c82cdbab995821e"
       "ec1e91ae1c738c60602becdaa2c68049efc48e8efa17054cdfb487bd3ccf137fe7e517dbee90eef07123d231ea794fa5"
        // clang-format on
    );
    EXPECT_GAS_USED(EVMC_SUCCESS, 58);
    EXPECT_EQ(hex(bytes_view(result.output_data, result.output_size)),
        "3c119b3934156e9d9a495378725bb6c7fdcd12784743919063f5a383d2d2af117e025fdb0fb03fa723a62a4d6d"
        "968d2b");
}

TEST_P(evm, mulmodmont384_garbage)
{
    rev = EVMC_ISTANBUL;
    const auto indices_packed = push("00000000000000000000003000000060");  // 0,0,48,96

    const auto code = calldatacopy(0, 0, OP_CALLDATASIZE) + indices_packed + "c2" + ret(0, 48);
    execute(code,
        // clang-format off
        "2d68c6c3a8b1f5a1077ef949836ddc178987ad09e0723f3d9a4aa95f50661652cb9a677b35e122903028f807272c104a"
        "f1562b8a749c87046d34a6d1101226508bb99a91982faeac365505dc7d9366404d9808a02531e3e80c82cdbab995821e"
        "ec1e91ae1c738c60602becdaa2c68049efc48e8efa17054cdfb487bd3ccf137fe7e517dbee90eef07123d231ea794fa5"
        "ffffffffffffffff"  // garbage inv
        // clang-format on
    );
    EXPECT_GAS_USED(EVMC_SUCCESS, 74);
    EXPECT_EQ(hex(bytes_view(result.output_data, result.output_size)),
        "b0f9fdbafea7416d7d306f04e96da1f87f72296a25bdb9263fbd57a66982d129208bf5683e3191274250b21744"
        "c12997");
}
