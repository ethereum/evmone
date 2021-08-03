# Changelog

Documentation of all notable changes to the **evmone** project.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].


## [0.8.1] — 2021-08-03

### Fixed

- baseline: Fix incorrect exit after invalid jump.
  [#370](https://github.com/ethereum/evmone/pull/370)


## [0.8.0] — 2021-07-01

## Added

- Full support for **[London]** EVM revision:
  - [EVMC] upgraded to version [9.0.0][EVMC 9.0.0].
    [#348](https://github.com/ethereum/evmone/pull/348)
  - Implementation of the [EIP-3198] "BASEFEE opcode".
    [#333](https://github.com/ethereum/evmone/pull/333)
- Instruction tracing ([EIP-3155]) can be enabled via `trace` option in Baseline.
  [#325](https://github.com/ethereum/evmone/pull/325)
- Summary of number of executed opcodes is reported if `histogram` option is enabled in Baseline.
  [#323](https://github.com/ethereum/evmone/pull/323)
- The `evmone-bench` now reports time of execution without code analysis under "execute" label.
  The EVMC-like analysis + execution invocation is reported as "total".
  [#343](https://github.com/ethereum/evmone/pull/343)
- The `evmone-bench` has started utilizing `evmc::MockedHost` which allows using
  state-access (e.g. `SLOAD`/`SSTORE`) instructions in benchmarks.
  [#319](https://github.com/ethereum/evmone/pull/319)

### Changed

- Improvements to semi-public `evmone::baseline` API.
  [#314](https://github.com/ethereum/evmone/pull/314)
- The [intx] has been upgraded to version [0.6.0][intx 0.6.0]
  which increases performance of `ADDMOD` instruction.
  [#345](https://github.com/ethereum/evmone/pull/345)
- The [ethash] has been upgraded to version [0.7.0][ethash 0.7.0]
  which provides faster `KECCAK256` implementation.
  [#332](https://github.com/ethereum/evmone/pull/332)
- Optimizations in Baseline interpreter.
  [#315](https://github.com/ethereum/evmone/pull/315)
  [#341](https://github.com/ethereum/evmone/pull/341)
  [#344](https://github.com/ethereum/evmone/pull/344)
- The Ethereum Consensus Tests upgraded to version [9.0.2][tests 9.0.2].
  [#349](https://github.com/ethereum/evmone/pull/349)


## [0.7.0] — 2021-04-27

### Added

- Full support for **[Berlin]** EVM revision and [EIP-2929].
  [#289](https://github.com/ethereum/evmone/pull/289)
  [#301](https://github.com/ethereum/evmone/pull/301)

### Changed

- [EVMC] has been upgraded to version [8.0.0][EVMC 8.0.0]. This ABI breaking
  change has been required to support **Berlin** revision.
  [#309](https://github.com/ethereum/evmone/pull/309)
- Optimizations to basic `JUMPDEST` analysis used by Baseline interpreter.
  [#306](https://github.com/ethereum/evmone/pull/306)
  [#308](https://github.com/ethereum/evmone/pull/308)
- The Baseline interpreter API has been modified to allow caching
  of the `JUMPDEST` analysis.
  [#305](https://github.com/ethereum/evmone/pull/305)
- The consensus testing is now driven by [Silkworm] as a replacement of 
  the unmaintained [Aleth]. The Ethereum Consensus Tests [8.0.4][tests 8.0.4] are currently being used.


## [0.6.0] — 2021-04-07

### Added

- New experimental **Baseline** interpreter has been added to the project.
  It provides relatively straight-forward EVM implementation and
  can be enabled with `O=0` option.
  [#261](https://github.com/ethereum/evmone/pull/261)
  [#280](https://github.com/ethereum/evmone/pull/280)
- A set of EVM synthetic benchmarks stressing individual
  low-level EVM instructions.
  [#278](https://github.com/ethereum/evmone/pull/278)
- [Silkworm]-driven integration and Ethereum consensus testing.
  [#290](https://github.com/ethereum/evmone/pull/290)

### Changed

- [EVMC] upgraded to version [7.5.0][EVMC 7.5.0].
  [#294](https://github.com/ethereum/evmone/pull/294)
- `evmone-bench` tool under-the-hood improvements.
  [#286](https://github.com/ethereum/evmone/pull/286)
  [#287](https://github.com/ethereum/evmone/pull/287)
  [#288](https://github.com/ethereum/evmone/pull/288)
- A lot of instructions implementation refactoring to allow code sharing
  between Baseline and Advanced interpreters.


## [0.5.0] — 2020-06-24

### Changed

- [intx] upgraded to version [0.5.0][intx 0.5.0], small performance increase for
  `ADDMOD` and `MULMOD` instructions expected.
  [#239](https://github.com/ethereum/evmone/pull/239)
- [EVMC] upgraded to version [7.4.0][EVMC 7.4.0].
  [#243](https://github.com/ethereum/evmone/pull/243)
- C++ exception handling and Run-Time Type Information (RTTI) have been disabled
  for the evmone library (in GCC and Clang compilers).
  [#244](https://github.com/ethereum/evmone/pull/244)


## [0.4.1] — 2020-04-01

### Fixed

- The release binaries for Windows are now built without AVX instruction set
  enabled. That was never intended and is consistent with binaries for other 
  operating systems.
  [#230](https://github.com/ethereum/evmone/pull/230)

## [0.4.0] — 2019-12-09

### Fixed

- In previous versions evmone incorrectly assumed that code size cannot exceed
  24576 bytes (0x6000) — the limit introduced for the size of newly deployed
  contracts by [EIP-170] in [Spurious Dragon]. The limit do not apply to
  contract creating init code (i.e. in context of "create" transaction or CREATE
  instruction). Therefore, the pre-processing phase in evmone has been reworked
  to raise the technical limits or eliminated them entirely. From now on, only
  blocks of instruction with total base gas cost exceeding 4294967295 (2³² - 1)
  combined with execution gas limit also above this value can cause issues.
  [#217](https://github.com/ethereum/evmone/pull/217)
  [#218](https://github.com/ethereum/evmone/pull/218)
  [#219](https://github.com/ethereum/evmone/pull/219)
  [#221](https://github.com/ethereum/evmone/pull/221)

### Changed

- [EVMC] has been upgraded to version [7.1.0][EVMC 7.1.0].
  [#212](https://github.com/ethereum/evmone/pull/212)

## [0.3.0] — 2019-11-14

This release of evmone adds changes for **[Istanbul]** EVM revision.

### Added

- **Istanbul** EVM revision support with new costs for some instructions ([EIP-1884]).
  [#191](https://github.com/ethereum/evmone/pull/191)
- Implementation of CHAINID instruction from the **Istanbul** EVM revision ([EIP-1344]).
  [#190](https://github.com/ethereum/evmone/pull/190)
- Implementation of SELFBALANCE instruction from the **Istanbul** EVM revision ([EIP-1884]).
  [#24](https://github.com/ethereum/evmone/pull/24)
- Implementation of new cost model for SSTORE from the **Istanbul** EVM revision ([EIP-2200]).
  [#142](https://github.com/ethereum/evmone/pull/142)

### Changed

- [EVMC] has been upgraded to version [7.0.0][EVMC 7.0.0].
  [#204](https://github.com/ethereum/evmone/pull/204)


## [0.2.0] — 2019-09-24

This release of evmone is binary compatible with 0.1 and delivers big performance improvements
– both code preprocessing and execution is **~66%** faster (needs ~40% less time).

### Added

- **evm-test** – the testing tool for [EVMC]-compatible EVM implementations.
  [#85](https://github.com/ethereum/evmone/pull/85)
- **evmone-fuzzer** – the testing tool that fuzzes evmone execution against [aleth-interpreter][Aleth] execution.
  Any other [EVMC]-compatible EVM implementation can be added easily.
  [#162](https://github.com/ethereum/evmone/pull/162)
  [#184](https://github.com/ethereum/evmone/pull/184)
- **evmone-standalone** – single static library that bundles evmone with all its static library dependencies 
  (available on Linux, but support can be extended to other platforms).
  [#95](https://github.com/ethereum/evmone/pull/95)
- The **evmone-bench** tool has learned how to benchmark external [EVMC]-compatible EVMs.
  [#111](https://github.com/ethereum/evmone/pull/111)
- The **evmone-bench** tool sorts test cases by file names and allows organizing them in subfolders.
  [#150](https://github.com/ethereum/evmone/pull/150)
- The docker image [ethereum/evmone](https://hub.docker.com/r/ethereum/evmone)
  with evmone and modified geth is available on Docker Hub.
  [#127](https://github.com/ethereum/evmone/pull/127)


### Changed

#### Optimizations

- Instead of checking basic block preconditions (base gas cost, stack requirements) in the dispatch loop, 
  this is now done in the special "BEGINBLOCK" instruction — execution time reduction **-2–8%**.
  [#74](https://github.com/ethereum/evmone/pull/74)
- New EVM stack implementation has replaced naïve usage of `std::vector<intx::uint256>` — **-8–16%**.
  [#79](https://github.com/ethereum/evmone/pull/79)
- Improvements to interpreter's dispatch loop — **-4–9%**.
  [#107](https://github.com/ethereum/evmone/pull/107)
- Optimization of the JUMPDEST map — up to **-34%**.
  [#80](https://github.com/ethereum/evmone/pull/80)
- Optimizations to code preprocessing / analysis.
  [#121](https://github.com/ethereum/evmone/pull/121)
  [#125](https://github.com/ethereum/evmone/pull/125)
  [#153](https://github.com/ethereum/evmone/pull/153)
  [#168](https://github.com/ethereum/evmone/pull/168)
  [#178](https://github.com/ethereum/evmone/pull/178)
- Push instructions with values up to 8 bytes (PUSH1–PUSH8)
  are now handled much more efficiently — up to **-9%**.
  [#122](https://github.com/ethereum/evmone/pull/122)
- Pointer to next instruction is now obtained in instruction implementations 
  (instead of the dispatch loop) and is kept in CPU registers only — **-3–7%**.
  [#133](https://github.com/ethereum/evmone/pull/133)
- The run-time information about basic blocks has been compressed.
  [#139](https://github.com/ethereum/evmone/pull/139)
  [#144](https://github.com/ethereum/evmone/pull/144)
  
#### Other changes

- The DUP, SWAP, LOG and CALL instructions are now implemented by individual functions (template instances)
  instead of a parametrized function handling each family of instructions.
  [#126](https://github.com/ethereum/evmone/pull/126)
  [#159](https://github.com/ethereum/evmone/pull/159)
- [EVMC] upgraded to version [6.3.1](https://github.com/ethereum/evmc/releases/tag/v6.3.1).
  [#129](https://github.com/ethereum/evmone/pull/129)
  [#77](https://github.com/ethereum/evmone/pull/77)
  [#96](https://github.com/ethereum/evmone/pull/96)
- [intx] upgraded to version [0.4.0](https://github.com/chfast/intx/releases/tag/v0.4.0).
  [#131](https://github.com/ethereum/evmone/pull/131)
- The ability to provide custom opcode table for code preprocessing has been dropped.
  [#167](https://github.com/ethereum/evmone/pull/167)


### Fixed

- The gas calculation for blocks containing an undefined instruction has been fixed.
  This bug could not cause consensus issue because a block with an undefined instruction terminates 
  with an exception despite incorrect gas checking.
  However, execution might have ended with a confusing error code.
  [#93](https://github.com/ethereum/evmone/pull/93)
- Fix for LOG being emitted after _out-of-gas_ exception.
  [#120](https://github.com/ethereum/evmone/pull/120)


## [0.1.1] — 2019-09-11

### Changed

- [EVMC] upgraded to version 6.3.1 (still ABI-compatible with evmone 0.1.0).
  [#171](https://github.com/ethereum/evmone/pull/171)
- Changes to the **evmone-bench** tool backported from 0.2. 
  This allows better performance comparison between 0.1 and 0.2 as both versions
  can run the same set of benchmarks.
  [#172](https://github.com/ethereum/evmone/pull/172)


## [0.1.0] — 2019-06-19

The first release of the evmone project. 
It delivers fully-compatible and high-speed EVM implementation.

### Added

- Support for all current EVM revisions up to [Petersburg].
- Exposes [EVMC] 6 ABI.
- The [intx 0.2.0](https://github.com/chfast/intx/releases/tag/v0.2.0) library is used for 256-bit precision arithmetic. 


[0.8.1]: https://github.com/ethereum/evmone/releases/tag/v0.8.1
[0.8.0]: https://github.com/ethereum/evmone/releases/tag/v0.8.0
[0.7.0]: https://github.com/ethereum/evmone/releases/tag/v0.7.0
[0.6.0]: https://github.com/ethereum/evmone/releases/tag/v0.6.0
[0.5.0]: https://github.com/ethereum/evmone/releases/tag/v0.5.0
[0.4.1]: https://github.com/ethereum/evmone/releases/tag/v0.4.1
[0.4.0]: https://github.com/ethereum/evmone/releases/tag/v0.4.0
[0.3.0]: https://github.com/ethereum/evmone/releases/tag/v0.3.0
[0.2.0]: https://github.com/ethereum/evmone/releases/tag/v0.2.0
[0.1.1]: https://github.com/ethereum/evmone/releases/tag/v0.1.1
[0.1.0]: https://github.com/ethereum/evmone/releases/tag/v0.1.0

[Aleth]: https://github.com/ethereum/aleth
[EIP-170]: https://eips.ethereum.org/EIPS/eip-170
[EIP-1884]: https://eips.ethereum.org/EIPS/eip-1884
[EIP-1344]: https://eips.ethereum.org/EIPS/eip-1344
[EIP-2200]: https://eips.ethereum.org/EIPS/eip-2200
[EIP-2929]: https://eips.ethereum.org/EIPS/eip-2929
[EIP-3155]: https://eips.ethereum.org/EIPS/eip-3155
[EIP-3198]: https://eips.ethereum.org/EIPS/eip-3198
[Spurious Dragon]: https://eips.ethereum.org/EIPS/eip-607
[Petersburg]: https://eips.ethereum.org/EIPS/eip-1716
[Istanbul]: https://eips.ethereum.org/EIPS/eip-1679
[Berlin]: https://github.com/ethereum/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md
[London]: https://github.com/ethereum/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/london.md
[EVMC]: https://github.com/ethereum/evmc
[EVMC 9.0.0]: https://github.com/ethereum/evmc/releases/tag/v9.0.0
[EVMC 8.0.0]: https://github.com/ethereum/evmc/releases/tag/v8.0.0
[EVMC 7.5.0]: https://github.com/ethereum/evmc/releases/tag/v7.5.0
[EVMC 7.4.0]: https://github.com/ethereum/evmc/releases/tag/v7.4.0
[EVMC 7.1.0]: https://github.com/ethereum/evmc/releases/tag/v7.1.0
[EVMC 7.0.0]: https://github.com/ethereum/evmc/releases/tag/v7.0.0
[intx]: https://github.com/chfast/intx
[intx 0.6.0]: https://github.com/chfast/intx/releases/tag/v0.6.0
[intx 0.5.0]: https://github.com/chfast/intx/releases/tag/v0.5.0
[ethash]: https://github.com/chfast/ethash
[ethash 0.7.0]: https://github.com/chfast/ethash/releases/tag/v0.7.0
[Silkworm]: https://github.com/torquem-ch/silkworm
[tests 8.0.4]: https://github.com/ethereum/tests/releases/tag/8.0.4
[tests 9.0.2]: https://github.com/ethereum/tests/releases/tag/9.0.2
[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org
