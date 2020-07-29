#include "evm_fixture.hpp"

using namespace evmc::literals;
using evm_calls = evm;

void test(){
  auto code = bytecode{};
  code += "6001600003600052";              // m[0] = 0xffffff...
  code += "600560046003600260016103e8f4";  // DELEGATECALL(1000, 0x01, ...)
  code += "60086000f3";

  auto call_output = bytes{0xa, 0xb, 0xc};
  host.call_result.output_data = call_output.data();
  host.call_result.output_size = call_output.size();
  host.call_result.gas_left = 1;

  execute(1700, code);
  printf("expect gas_used = 1690, actual gas_used = %d\n", gas_used);
}

int main(){
  test();
  return 0;
}
