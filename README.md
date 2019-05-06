# evmone

[![readme style: standard][readme style standard badge]][standard readme]

> Fast Ethereum Virtual Machine implementation

The C++ implementation of the Ethereum Virtual Machine (EVM) focused on speed.
Compatible with [EVMC].

Uses [intx] as a bignumber library and [ethash] for the special `SHA3` opcode.

## Usage

To build EVMC module (shared library), test or benchmark.

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

Licensed under the [Apache License, Version 2.0].


[@chfast]: https://github.com/chfast
[Apache License, Version 2.0]: LICENSE
[EVMC]: https://github.com/ethereum/evmc
[intx]: https://github.com/chfast/intx
[ethash]: https://github.com/chfast/ethash
[standard readme]: https://github.com/RichardLitt/standard-readme

[readme style standard badge]: https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square
