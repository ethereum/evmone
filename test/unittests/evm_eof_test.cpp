// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using namespace evmc::literals;
using evmone::test::evm;

TEST_P(evm, eof1_execution)
{
    const auto code = eof_bytecode(OP_STOP);

    rev = EVMC_CANCUN;
    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    rev = EVMC_PRAGUE;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, eof1_execution_with_data_section)
{
    rev = EVMC_PRAGUE;
    // data section contains ret(0, 1)
    const auto code = eof_bytecode(mstore8(0, 1) + OP_STOP, 2).data(ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_PRAGUE;
    auto code = eof_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 28);

    code = eof_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), 2).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 32);
}

TEST_P(evm, eof1_codecopy_full)
{
    rev = EVMC_PRAGUE;
    auto code = eof_bytecode(bytecode{31} + 0 + 0 + OP_CODECOPY + ret(0, 31), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c0400000000800003601f6000600039601f6000f3"_hex);

    code = eof_bytecode(bytecode{35} + 0 + 0 + OP_CODECOPY + ret(0, 35), 3).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c04000400008000036023600060003960236000f3deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_header)
{
    rev = EVMC_PRAGUE;
    auto code = eof_bytecode(bytecode{15} + 0 + 0 + OP_CODECOPY + ret(0, 15), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), "ef0001010004020001000c04000000"_hex);

    code = eof_bytecode(bytecode{15} + 0 + 0 + OP_CODECOPY + ret(0, 15), 3).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), "ef0001010004020001000c04000400"_hex);
}

TEST_P(evm, eof1_codecopy_code)
{
    rev = EVMC_PRAGUE;
    auto code = eof_bytecode(bytecode{12} + 19 + 0 + OP_CODECOPY + ret(0, 12), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c6013600039600c6000f3"_hex);

    code = eof_bytecode(bytecode{12} + 19 + 0 + OP_CODECOPY + ret(0, 12), 3).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c6013600039600c6000f3"_hex);
}

TEST_P(evm, eof1_codecopy_data)
{
    rev = EVMC_PRAGUE;

    const auto code =
        eof_bytecode(bytecode{4} + 31 + 0 + OP_CODECOPY + ret(0, 4), 3).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_out_of_bounds)
{
    // 4 bytes out of container bounds - result is implicitly 0-padded
    rev = EVMC_PRAGUE;
    auto code = eof_bytecode(bytecode{35} + 0 + 0 + OP_CODECOPY + ret(0, 35), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c04000000008000036023600060003960236000f300000000"_hex);

    code = eof_bytecode(bytecode{39} + 0 + 0 + OP_CODECOPY + ret(0, 39), 3).data("deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c04000400008000036027600060003960276000f3deadbeef00000000"_hex);
}

TEST_P(evm, eof_data_only_contract)
{
    rev = EVMC_PRAGUE;
    auto code = "EF0001 010004 020001 0001 04daaa 00 00800000 FE"_hex;
    const auto data_size_ptr = &code[code.find(0xda)];

    intx::be::unsafe::store(data_size_ptr, uint16_t{0});
    execute(code);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);

    intx::be::unsafe::store(data_size_ptr, uint16_t{1});
    execute(code + "aa"_hex);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);

    intx::be::unsafe::store(data_size_ptr, uint16_t{256});
    execute(code + bytes(256, 0x01));
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);
}

TEST_P(evm, eof1_dataload)
{
    // Data instructions are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    // data is 64 bytes long
    const auto data = bytes(8, 0x0) + bytes(8, 0x11) + bytes(8, 0x22) + bytes(8, 0x33) +
                      bytes(8, 0xaa) + bytes(8, 0xbb) + bytes(8, 0xcc) + bytes(8, 0xdd);
    const auto code = eof_bytecode(calldataload(0) + OP_DATALOAD + ret_top(), 2).data(data);

    // DATALOAD(0)
    execute(code, "00"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000111111111111111122222222222222223333333333333333"_hex);

    // DATALOAD(1)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000001"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "00000000000000111111111111111122222222222222223333333333333333aa"_hex);

    // DATALOAD(2)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000020"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"_hex);

    // DATALOAD(33) - truncated word
    execute(code, "0000000000000000000000000000000000000000000000000000000000000021"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "aaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd00"_hex);

    // DATALOAD(64) - out of data bounds
    execute(code, "0000000000000000000000000000000000000000000000000000000000000040"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);

    // DATALOAD(u256_max) - out of data bounds
    execute(code, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);
}

TEST_P(evm, eof1_dataloadn)
{
    // Data instructions are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    // data is 64 bytes long
    const auto data = bytes(8, 0x0) + bytes(8, 0x11) + bytes(8, 0x22) + bytes(8, 0x33) +
                      bytes(8, 0xaa) + bytes(8, 0xbb) + bytes(8, 0xcc) + bytes(8, 0xdd);

    // DATALOADN{0}
    auto code = eof_bytecode(bytecode(OP_DATALOADN) + "0000" + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000111111111111111122222222222222223333333333333333"_hex);

    // DATALOADN{1}
    code = eof_bytecode(bytecode(OP_DATALOADN) + "0001" + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "00000000000000111111111111111122222222222222223333333333333333aa"_hex);

    // DATALOADN{32}
    code = eof_bytecode(bytecode(OP_DATALOADN) + "0020" + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"_hex);
}

TEST_P(evm, eof1_datasize)
{
    // Data instructions are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;

    // no data section
    auto code = eof_bytecode(bytecode(OP_DATASIZE) + ret_top(), 2);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);

    bytes data = {0x0};
    code = eof_bytecode(bytecode(OP_DATASIZE) + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000001"_hex);

    data = bytes(32, 0x0);
    code = eof_bytecode(bytecode(OP_DATASIZE) + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000020"_hex);

    data = bytes(64, 0x0);
    code = eof_bytecode(bytecode(OP_DATASIZE) + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000040"_hex);

    data = bytes(80, 0x0);
    code = eof_bytecode(bytecode(OP_DATASIZE) + ret_top(), 2).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000050"_hex);
}

TEST_P(evm, eof1_datacopy)
{
    // Data instructions are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    // data is 64 bytes long
    const auto data = bytes(8, 0x0) + bytes(8, 0x11) + bytes(8, 0x22) + bytes(8, 0x33) +
                      bytes(8, 0xaa) + bytes(8, 0xbb) + bytes(8, 0xcc) + bytes(8, 0xdd);

    auto code = eof_bytecode(bytecode(1) + 0 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(1) + 8 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "1100000000000000000000000000000000000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(1) + 63 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "dd00000000000000000000000000000000000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(0) + 64 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(16) + 8 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "1111111111111111222222222222222200000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(32) + 8 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "111111111111111122222222222222223333333333333333aaaaaaaaaaaaaaaa"_hex);

    code = eof_bytecode(bytecode(8) + 63 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "dd00000000000000000000000000000000000000000000000000000000000000"_hex);

    code = eof_bytecode(bytecode(0) + 65 + 0 + OP_DATACOPY + ret(0, 32), 3).data(data);
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "0000000000000000000000000000000000000000000000000000000000000000"_hex);
}

TEST_P(evm, datacopy_memory_cost)
{
    // Data instructions are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    const auto data = bytes{0};
    const auto code = eof_bytecode(bytecode(1) + 0 + 0 + OP_DATACOPY + OP_STOP, 3).data(data);
    execute(18, code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 18);

    execute(17, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);
}

TEST_P(evm, eof_create3)
{
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const bytecode deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + OP_CALLDATASIZE + 0 + OP_RETURNCONTRACT + Opcode{0};
    const auto init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto create_code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                             create3().input(0, OP_CALLDATASIZE).salt(0xff) + ret_top();
    const auto container = eof_bytecode(create_code, 4).container(init_container);

    // test executing create code mocking CREATE3 call
    host.call_result.output_data = deploy_container.data();
    host.call_result.output_size = deploy_container.size();
    host.call_result.create_address = 0xcc010203040506070809010203040506070809ce_address;

    execute(container, aux_data);
    EXPECT_STATUS(EVMC_SUCCESS);

    ASSERT_EQ(host.recorded_calls.size(), 1);
    const auto& call_msg = host.recorded_calls.back();

    EXPECT_EQ(call_msg.input_size, aux_data.size());

    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(output, "000000000000000000000000cc010203040506070809010203040506070809ce"_hex);

    // test executing initcontainer
    msg.kind = EVMC_CREATE3;
    execute(init_container, aux_data);
    EXPECT_STATUS(EVMC_SUCCESS);
    const bytecode deployed_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data + aux_data);
    ASSERT_EQ(result.output_size, deployed_container.size());
    EXPECT_EQ(output, deployed_container);
}

TEST_P(evm, create3_undefined_in_legacy)
{
    rev = EVMC_CANCUN;
    const auto code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                      create3().input(0, OP_CALLDATASIZE).salt(0xff) + ret_top();

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, returncontract_undefined_in_legacy)
{
    rev = EVMC_CANCUN;
    const auto code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + OP_CALLDATASIZE + 0 + OP_RETURNCONTRACT + Opcode{0};

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}
