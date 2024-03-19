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

    rev = EVMC_PRAGUE;

    const auto eof_code = bytecode(
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0001"  //          1 code section 1 byte long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0000"          //                 first code section has max stack height 0
        "00"            // Code section - STOP
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

    rev = EVMC_PRAGUE;

    const auto eof_code = bytecode(
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0003"  //          1 code section 3 bytes long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0000"          //                 first code section has max stack height 0
        "E0FFFD"        // Code section - RJUMP back to start (-3) - infinite loop
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

    rev = EVMC_PRAGUE;

    const auto eof_code = bytecode(
        "EF00 01"         // EOF prefix and version 1
        "01 0008"         // Header - types section 8 bytes long
        "02 0002"         //          2 code sections:
        "0006"            //            - first code section 6 bytes long
        "0001"            //            - second code section 1 byte long
        "04 0000"         //          data section 0 bytes long
        "00"              // Header terminator
        "00"              // Types section - first code section 0 inputs
        "80"              //                 first code section non-returning
        "0001"            //                 first code section has max stack height 1
        "01"              //                 second code section 1 input
        "01"              //                 second code section 1 output
        "0001"            //                 second code section has max stack height 1
        "602A E30001 00"  // First code section - PUSH1(42), CALLF second section and STOP
        "E4"              // Second code section - just return (RETF) the input
    );

    // Tests the code is valid EOF.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_txcreate)
{
    // # Example 4
    //
    // A very basic deployer contract with a TXCREATE instruction is being called in an
    // InitcodeTransaction in order to create a new EOF contract.

    rev = EVMC_PRAGUE;

    const auto initcontainer = bytecode(
        //////////////////
        // Initcontainer
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0004"  //          1 code section 4 bytes long
        "03 0001 0014"  //          1 subcontainer 20 bytes long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0002"          //                 first code section has max stack height 2
        "5F5F"          // Code section - PUSH0 [aux data size] + PUSH0 [aux data offset]
        "EE00"          //                RETURNCONTRACT first subcontainer
        //////////////////
        // Deployed container (contract doing nothing)
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0001"  //          1 code section 1 byte long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0000"          //                 first code section has max stack height 0
        "00"            // Code section - STOP
    );

    const auto initcontainer_hash = keccak256(initcontainer);

    const auto deployer = bytecode(
        //////////////////
        // Deployer container
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0028"  //          1 code section 40 bytes long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0005"          //                 first code section has max stack height 5
        "5F 5F 60FF"    // Code section - PUSH0 [input size] + PUSH0 [input offset] + PUSH1 [salt] +
        "5F 7F" +       // PUSH0 [endowment value] + PUSH32 [initcode hash]
        hex(initcontainer_hash) +
        "ED 00"  // TXCREATE and STOP
    );

    // Put the initcontainer in the `initcodes` field of an InitcodeTransaction.
    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(initcontainer);

    // Tests the code is valid EOF and when called with initcodes creates a new contract.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = deployer,
                       });

    // Address of the newly created contract is calculated using the salt, initcontainer hash and
    // deployer address.
    expect.post[0x5ea44d9b32a04ae2c15fe4fa8ebf9a8a5a1e7e89_address].exists = true;
    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, eof_examples_eofcreate)
{
    // # Example 5
    //
    // A factory contract with an EOFCREATE instruction is being called in order
    // to deploy its subcontainer as a new EOF contract.

    rev = EVMC_PRAGUE;

    const auto factory = bytecode(
        //////////////////
        // Factory container
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0008"  //          1 code section 8 bytes long
        "03 0001 0030"  //          1 subcontainer 20+28=48 bytes long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0004"          //                 first code section has max stack height 4
        "5F 5F 60FF"    // Code section - PUSH0 [input size] + PUSH0 [input offset] + PUSH1 [salt] +
        "5F"            // PUSH0 [endowment value]
        "EC00"          // EOFCREATE from first subcontainer
        "00"            // STOP
        //////////////////
        // Initcontainer
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0004"  //          1 code section 4 bytes long
        "03 0001 0014"  //          1 subcontainer 20 bytes long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0002"          //                 first code section has max stack height 2
        "5F 5F"         // Code section - PUSH0 [aux data size] + PUSH0 [aux data offset]
        "EE00"          //                RETURNCONTRACT first subcontainer
        //////////////////
        // Deployed container (contract doing nothing)
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0001"  //          1 code section 1 byte long
        "04 0000"       //          data section 0 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0000"          //                 first code section has max stack height 0
        "00"            // Code section - STOP
    );

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

    rev = EVMC_PRAGUE;

    const auto eof_code = bytecode(
        "EF00 01"       // EOF prefix and version 1
        "01 0004"       // Header - types section 4 bytes long
        "02 0001 0004"  //          1 code section 4 bytes long
        "04 0021"       //          data section 33 bytes long
        "00"            // Header terminator
        "00"            // Types section - first code section 0 inputs
        "80"            //                 first code section non-returning
        "0001"          //                 first code section has max stack height 1
        "D10000 00"     // Code section - DATALOADN onto the stack the first byte of data, then STOP
        "454F462068617320736F6D65206772656174206578616D706C6573206865726521"  // Data section
    );

    // Tests the code is valid EOF and does nothing.
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_code,
                       });

    expect.post[*tx.to].exists = true;
}
