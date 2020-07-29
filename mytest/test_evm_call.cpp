#include "evm_fixture.hpp"
#include <stdio.h>

using namespace evmc::literals;

void test(){
    auto code = bytecode{};
    code += "6001600003600052";              // m[0] = 0xffffff...
    code += "600560046003600260016103e8f4";  // DELEGATECALL(1000, 0x01, ...)
    code += "60086000f3";

    evm evmcall;
    auto call_output = bytes{0xa, 0xb, 0xc};
    evmcall.host.call_result.output_data = call_output.data();
    evmcall.host.call_result.output_size = call_output.size();
    evmcall.host.call_result.gas_left = 1;

    evmcall.execute(1700, code);

    printf("gase use = %d, expect 1690\n", evmcall.gas_used);
}

int main(){
  test();
  return 0;
}
