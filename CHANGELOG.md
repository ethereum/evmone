# Changelog

Documentation of all notable changes to the **evmone** project.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].

## [0.2.0] - unreleased
### Added
- **evm-test** - the testing tool for EVMC-compatible Ethereum Virtual Machine implementations
  [#85](https://github.com/ethereum/evmone/pull/85).


## [0.1.1] - 2019-09-11
### Changed
- [EVMC] upgraded to version 6.3.1 (still ABI-compatible with evmone 0.1.0).
  [[#171](https://github.com/ethereum/evmone/pull/171)]
- Changes to the **evmone-bench** tool backported from 0.2. 
  This allows better performance comparison between 0.1 and 0.2 as both versions
  can run the same set of benchmarks.
  [[#172](https://github.com/ethereum/evmone/pull/172)]


## [0.1.0] - 2019-06-19
### Added
- First release of the evmone project.
- Support for all current EVM revisions up to Petersburg.
- The [intx 0.2.0](https://github.com/chfast/intx/releases/tag/v0.2.0) library is used for 256-bit precision arithmetic. 


[0.2.0]: https://github.com/ethereum/evmone/compare/v0.1.0..master
[0.1.1]: https://github.com/ethereum/evmone/releases/tag/v0.1.1
[0.1.0]: https://github.com/ethereum/evmone/releases/tag/v0.1.0

[EVMC]: https://github.com/ethereum/evmc
[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org
