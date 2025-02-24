#include "expmod.hpp"

using namespace evmone::test;
using namespace intx;

namespace
{
bytecode calc_odd_modulus(bytecode base_mem_offset, bytecode base_size, bytecode exp_mem_offset,
    bytecode exp_size, bytecode mod_mem_offset, bytecode mod_size)
{
    bytecode ret;
    ret += setmodx(256, mod_size, mod_mem_offset);
    ret += storex(1, base_mem_offset, 0);

    ret += rjumpi(revert(0, 0), eq(mod_(exp_size, 32), 0));

    ret += div(exp_size, 32) + push0() + OP_DUP2 + OP_DUP2;

    bytecode inner_loop_bytecode = mload(add(exp_mem_offset, mul(bytecode() + OP_DUP1, 32)));
    inner_loop_bytecode += push(255) + push(1) + OP_SHL;
    inner_loop_bytecode += rjumpi(bytecode(), not_(bytecode() + OP_DUP1));


    ret += rjumpi(bytecode(), not_(bytecode() + OP_LT));


    return ret;
}

}  // namespace

bytecode create_expmod_bytecode()
{
    bytecode ret;
    // Call data size must have at least 96 bytes
    ret += rjumpi(revert(0, 0), not_(lt(calldatasize(), 96)));
    // Call data size must have (96 + base_size + exp_size + mod_size) bytes.
    ret += rjumpi(revert(0, 0),
        eq(calldatasize(), add(96, add(add(calldataload(0), calldataload(32)), calldataload(64)))));


    ret += rjumpi()

        return ret;
}
