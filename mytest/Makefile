test_evm_call: test_evm_call.cpp vm_loader_evmone.cpp
	riscv64-unknown-linux-gnu-g++ vm_loader_evmone.cpp test_evm_call.cpp -o  test_evm_call -I../evmc/include/ -I../include/ -I../../intx-0.4.0/include/ -I../ -std=c++17 ../build/lib/libevmone.a ../build/lib/libtestutils.a ../../ethash/build/lib/keccak/libkeccak.a ../../intx-0.4.0/build/lib/intx/libintx.a
