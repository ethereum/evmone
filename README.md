# evmone

[![ethereum badge]][ethereum]
[![readme style standard badge]][standard readme]
[![codecov badge]][codecov]
[![circleci badge]][circleci]
[![appveyor badge]][appveyor]
[![license badge]][Apache License, Version 2.0]

> Fast Ethereum Virtual Machine implementation

The C++ implementation of the Ethereum Virtual Machine (EVM) focused on speed.
Compatible with [EVMC].

#### Characteristic of evmone

1. The "indirect" subroutine threading is the dispatch method - 
   a table with pointers to subroutines is prepared during the analysis of the bytecode.
2. The gas cost and stack requirements of block of instructions is precomputed 
   and applied once per block during execution.
3. The [intx] library is used to provide 256-bit integer precision.
4. The [ethash] library is used to provide Keccak hash function implementation
   needed for the special `SHA3` instruction.

## Usage

To build the evmone EVMC module (shared library), test or benchmark.

```bash
git clone --recursive https://github.com/chfast/evmone
cd evmone
mkdir build
cd build

cmake .. -DEVMONE_TESTING=ON
cmake --build . -- -j

bin/evmone-unittests
bin/evmone-bench
```

## Maintainer

Paweł Bylica [@chfast]

## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].


[@chfast]: https://github.com/chfast
[appveyor]: https://ci.appveyor.com/project/chfast/evmone/branch/master
[circleci]: https://circleci.com/gh/chfast/evmone/tree/master
[codecov]: https://codecov.io/gh/chfast/evmone/
[Apache License, Version 2.0]: LICENSE
[ethereum]: https://ethereum.org
[EVMC]: https://github.com/ethereum/evmc
[intx]: https://github.com/chfast/intx
[ethash]: https://github.com/chfast/ethash
[standard readme]: https://github.com/RichardLitt/standard-readme

[appveyor badge]: https://img.shields.io/appveyor/ci/chfast/evmone/master.svg?logo=appveyor
[circleci badge]: https://img.shields.io/circleci/project/github/chfast/evmone/master.svg?logo=circleci
[codecov badge]: https://img.shields.io/codecov/c/github/chfast/evmone.svg?logo=codecov
[ethereum badge]: https://img.shields.io/badge/ethereum-EVM-informational.svg?logo=ethereum
[license badge]: https://img.shields.io/github/license/chfast/evmone.svg?logo=apache
[readme style standard badge]: https://img.shields.io/badge/readme%20style-standard-brightgreen.svg
