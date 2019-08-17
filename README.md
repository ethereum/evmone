# evmone

[![ethereum badge]][ethereum]
[![readme style standard badge]][standard readme]
[![codecov badge]][codecov]
[![circleci badge]][circleci]
[![appveyor badge]][appveyor]
[![license badge]][Apache License, Version 2.0]

> Fast Ethereum Virtual Machine implementation

_evmone_ is a C++ implementation of the Ethereum Virtual Machine (EVM). 
Created by members of the [Ewasm] team, the project aims for clean, standalone EVM implementation 
that can be imported as an execution module by Ethereum Client projects. 
The codebase of _evmone_ is optimized to provide fast and efficient execution of EVM smart contracts.

#### Characteristic of evmone

1. Exposes the [EVMC] API.
2. The direct call threading is the dispatch method used -
   a loaded EVM program is a table with pointers to functions implementing virtual instructions.
3. The gas cost and stack requirements of block of instructions is precomputed 
   and applied once per block during execution.
4. The [intx] library is used to provide 256-bit integer precision.
5. The [ethash] library is used to provide Keccak hash function implementation
   needed for the special `SHA3` instruction.
6. Requires C++17 standard.

## Usage

### As geth plugin

evmone implements the [EVMC] API for Ethereum Virtual Machines.
It can be used as a plugin replacing geth's internal EVM. But for that a modified
version of geth is needed. The [Ewasm]'s fork
of go-ethereum provides [binary releases of geth with EVMC support](https://github.com/ewasm/go-ethereum/releases).

Next, download evmone from [Releases].

Start the downloaded geth with `--vm.evm` option pointing to the evmone shared library.

```bash
geth --vm.evm=./libevmone.so
```

### Building from source

To build the evmone EVMC module (shared library), test or benchmark.

```bash
git clone --recursive https://github.com/ethereum/evmone
cd evmone
mkdir build
cd build

cmake .. -DEVMONE_TESTING=ON
cmake --build . -- -j

bin/evmone-unittests
bin/evmone-bench
```

### Tools

#### evm-test

The **evm-test** executes a collection of unit tests on 
any EVMC-compatible Ethereum Virtual Machine implementation.
The collection of tests comes from the evmone project.

```bash
evm-test ./evmone.so
```

### Docker

Docker images with evmone and modified geth are available on Docker Hub:
https://hub.docker.com/r/ethereum/evmone.

```bash
docker run ethereum/evmone --vm.evm=libevmone.so
```

## Maintainer

Paweł Bylica [@chfast]

## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].


[@chfast]: https://github.com/chfast
[appveyor]: https://ci.appveyor.com/project/chfast/evmone/branch/master
[circleci]: https://circleci.com/gh/ethereum/evmone/tree/master
[codecov]: https://codecov.io/gh/ethereum/evmone/
[Apache License, Version 2.0]: LICENSE
[ethereum]: https://ethereum.org
[EVMC]: https://github.com/ethereum/evmc
[Ewasm]: https://github.com/ewasm
[intx]: https://github.com/chfast/intx
[ethash]: https://github.com/chfast/ethash
[Releases]: https://github.com/ethereum/evmone/releases
[standard readme]: https://github.com/RichardLitt/standard-readme

[appveyor badge]: https://img.shields.io/appveyor/ci/chfast/evmone/master.svg?logo=appveyor
[circleci badge]: https://img.shields.io/circleci/project/github/ethereum/evmone/master.svg?logo=circleci
[codecov badge]: https://img.shields.io/codecov/c/github/ethereum/evmone.svg?logo=codecov
[ethereum badge]: https://img.shields.io/badge/ethereum-EVM-informational.svg?logo=ethereum
[license badge]: https://img.shields.io/github/license/ethereum/evmone.svg?logo=apache
[readme style standard badge]: https://img.shields.io/badge/readme%20style-standard-brightgreen.svg
