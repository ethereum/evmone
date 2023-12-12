# zkEVM1

> Direct compilation of Ethereum Virtual Machine

_zkEVM1_ is the first implementation of a zk-EVM compiled directly from a C++ EVM implementation.
It is based on _evmone_ -- a widely used C++ implementation of the Ethereum Virtual Machine (EVM).

### Characteristic of zkEVM1

1. Can be used both as an EVM and as a zk-EVM.
2. Fully compatible with _evmone_ EVM implementation.
3. Uses [crypto3](https://github.com/NilFoundation/crypto3) cryptography library to provide circuit-friendly cryptographic primitives.

## Usage

### Usage as an EVM

The _zkEVM1_ is fully compatible with _evmone_. Since we provide the same interface, you can use the usage instruction from [evmone usage documentation](https://github.com/ethereum/evmone#usage).

### Usage as a zk-EVM

# Binary Installation

zkLLVM is distributed as a deb package, so you can install it using the following commands:

```bash
echo 'deb [trusted=yes]  http://deb.nil.foundation/ubuntu/ all main' >>/etc/apt/sources.list
apt update
apt install -y zkllvm cmake libboost-all-dev
```

# Installation from sources

Sometimes you may want to install zkLLVM from sources. This is useful if you want to contribute to the project or if you want to use the latest version of the project.

## Clone repository

Clone the repository and all its submodules:

```
git clone --recurse-submodules git@github.com:NilFoundation/zkllvm.git
cd zkllvm
```

## **Configure cmake**

```bash
cmake -G "Unix Makefiles" -B ${ZKEVM1_BUILD:-build} -DCMAKE_BUILD_TYPE=Release .
```

## **Build**

```bash
 make -C ${ZKEVM1_BUILD:-build} evmone_circuit -j$(nproc) 
```

## **Generate Execution trace**

This generates an execution trace for the arithmetic example built.

```
$assigner -b ${ZKEVM1_BUILD:-build}/lib/evmone/evmone_circuit -i input-examples/input0.ll -t assignment.tbl -c circuit.crct
```

## **Generate the proof**

To generate the proof, you need to either local proof producer or to use the proof market CLI. 
Both approaches are described in [Proof Market usage documentation](https://github.com/NilFoundation/proof-market-toolchain/).

