// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

// This test file is serving as a set of examples of basic valid EOF codes,
// to be linked to from external specs and documentation.

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, eof_examples_minimal)
{
    // # Example 1
    //
    // A minimal valid EOF container doing nothing.

    rev = EVMC_OSAKA;

    const auto eof_code = bytecode(
        //                                                  Code section: STOP
        //               Header: 1 code section 1 byte long |
        //               |                                  |
        //    version    |                    Header terminator
        //    |          |___________         |             |
        "EF00 01 01 0004 02 0001 0001 04 0000 00 00 80 0000 00"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    Header: data section 0 bytes long
        //       |                               |
        //       Header: types section 4 bytes long
        //                                       |
        //                                       Types section: first code section 0 inputs,
        //                                       non-returning, max stack height 0
    );

    // Tests the code is valid EOF and does nothing.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_static_relative_jump_loop)
{
    // # Example 2
    //
    // EOF container looping infinitely using the static relative jump instruction RJUMP.

    rev = EVMC_OSAKA;

    const auto eof_code = bytecode(
        //                                                  Code section: RJUMP back to start (-3)
        //                                                  - infinite loop
        //                                                  |
        //               Header: 1 code section 3 bytes long
        //               |                                  |
        //    version    |                    Header terminator
        //    |          |___________         |             |
        "EF00 01 01 0004 02 0001 0003 04 0000 00 00 80 0000 E0FFFD"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    Header: data section 0 bytes long
        //       |                               |
        //       Header: types section 4 bytes long
        //                                       |
        //                                       Types section: first code section 0 inputs,
        //                                       non-returning, max stack height 0
    );

    // Tests the code is valid EOF and the infinite loop runs out of gas.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.status = EVMC_OUT_OF_GAS;
    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_callf)
{
    // # Example 3
    //
    // EOF container with two code sections, one calling the other passing a single argument on the
    // stack and retrieving the same single value back from the stack on return.

    rev = EVMC_OSAKA;

    const auto eof_code = bytecode(
        //                                                   First code section: PUSH1(0x2A),
        //                                                   CALLF second section and STOP
        //               Header: 2 code sections:                           |
        //               |       - first code section 6 bytes long          | Second code section:
        //               |       - second code section 1 byte long          | return the input
        //               |                                                  |              |
        //    version    |                         Header terminator        |              |
        //    |          |________________         |                        |_____________ |
        "EF00 01 01 0008 02 0002 0006 0001 04 0000 00 00 80 0001 01 01 0001 602A E30001 00 E4"
        //       |‾‾‾‾‾‾                   |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
        //       |                         Header: data section 0 bytes long
        //       |                                    |
        //       Header: types section 8 bytes long   |
        //                                            |
        //                                            Types section: first code section 0 inputs,
        //                                            non-returning, max stack height 1;
        //                                            second code section 1 input,
        //                                            1 output, max stack height 1
    );

    // Tests the code is valid EOF.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_creation_tx)
{
    // # Example 4
    //
    // A creation transaction used to create a new EOF contract.

    rev = EVMC_OSAKA;

    const auto initcontainer = bytecode(
        //////////////////
        // Initcontainer
        //                        Code section: PUSH0 [aux data size], PUSH0 [aux data offset] and
        //                                      RETURNCODE first subcontainer
        //                                                               |
        //               Header: 1 code section 4 bytes long             |
        //               |                                               |
        //    version    |                                 Header terminator
        //    |          |___________                      |             |________
        "EF00 01 01 0004 02 0001 0004 03 0001 0014 04 0000 00 00 80 0002 5F5F EE00"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾‾‾‾‾‾ |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    |            Header: data section 0 bytes long
        //       |                    |                       |
        //       Header: types section 4 bytes long           Types section: first code section
        //                            |                       0 inputs, non-returning,
        //                            |                       max stack height 2
        //       Header: 1 subcontainer 20 bytes long
        //
        //////////////////
        // Deployed container (contract doing nothing, see Example 1)
        "EF00 01 01 0004 02 0001 0001 04 0000 00 00 80 0000 00");

    // Put the initcontainer in the `data` field of the transaction, appending some calldata.
    tx.data = initcontainer + "ABCDEF";
    // Empty `to` field.
    tx.to = std::nullopt;

    // Address of the newly created contract is calculated using the deployer's address and nonce.
    expect.post[0x3442a1dec1e72f337007125aa67221498cdd759d_address].exists = true;
}

TEST_F(state_transition, eof_examples_eofcreate)
{
    // # Example 5
    //
    // A factory contract with an EOFCREATE instruction is being called in order
    // to deploy its subcontainer as a new EOF contract.

    rev = EVMC_OSAKA;

    const auto factory = bytecode(
        //////////////////
        // Factory container
        //                    Code section: PUSH0 [input size], PUSH0 [input offset], PUSH1 [salt],
        //                                  PUSH0 [endowment value],
        //                                  EOFCREATE from first subcontainer and STOP
        //                                                               |
        //               Header: 1 code section 8 bytes long             |
        //               |                                               |
        //    version    |                                 Header terminator
        //    |          |___________                      |             |____________________
        "EF00 01 01 0004 02 0001 0008 03 0001 0030 04 0000 00 00 80 0004 5F 5F 60FF 5F EC00 00"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾‾‾‾‾‾ |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    |            Header: data section 0 bytes long
        //       |                    |                       |
        //       Header: types section 4 bytes long           Types section: first code section
        //                            |                       0 inputs, non-returning,
        //                            |                       max stack height 4
        //       Header: 1 subcontainer 48 bytes long
        //
        //////////////////
        // Initcontainer
        //                    Code section: PUSH0 [aux data size], PUSH0 [aux data offset],
        //                                  RETURNCODE first subcontainer
        //                                                               |
        //               Header: 1 code section 4 bytes long             |
        //               |                                               |
        //    version    |                                 Header terminator
        //    |          |___________                      |             |_________
        "EF00 01 01 0004 02 0001 0004 03 0001 0014 04 0000 00 00 80 0002 5F 5F EE00"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾‾‾‾‾‾ |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    |            Header: data section 0 bytes long
        //       |                    |                       |
        //       Header: types section 4 bytes long           Types section: first code section
        //                            |                       0 inputs, non-returning,
        //                            |                       max stack height 2
        //       Header: 1 subcontainer 20 bytes long
        //
        //////////////////
        // Deployed container (contract doing nothing, see Example 1)
        "EF00 01 01 0004 02 0001 0001 04 0000 00 00 80 0000 00");

    // Tests the code is valid EOF and when called with initcodes creates a new contract.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = factory,
                       });

    // Address of the newly created contract is calculated using the salt, initcontainer hash and
    // deployer address.
    expect.post[0x5ea44d9b32a04ae2c15fe4fa8ebf9a8a5a1e7e89_address].exists = true;
    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_data)
{
    // # Example 6
    //
    // A basic EOF contract with a data section being used to load a byte of data onto the stack.

    rev = EVMC_OSAKA;

    // clang-format off
    const auto eof_code = bytecode(
        //                   Code section: DATALOADN onto the stack the first word of data, STOP
        //                                                  |
        //               Header: 1 code section 4 bytes long 
        //               |                                  |
        //    version    |                    Header terminator       Data section
        //    |          |___________         |             |________ |_________________________________________________________________
        "EF00 01 01 0004 02 0001 0004 04 0021 00 00 80 0001 D10000 00 454F462068617320736F6D65206772656174206578616D706C6573206865726521"
        //       |‾‾‾‾‾‾              |‾‾‾‾‾‾    |‾‾‾‾‾‾‾‾‾
        //       |                    Header: data section 33 bytes long
        //       |                               |
        //       Header: types section 4 bytes long
        //                                       |
        //                                       Types section: first code section 0 inputs,
        //                                       non-returning, max stack height 1
    );
    // clang-format on

    // Tests the code is valid EOF and does nothing.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.post[*tx.to].exists = true;
}
