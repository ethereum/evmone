# Changelog

Documentation of all notable changes to the **evmone** project.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].

## [0.10.0] — 2023-05-08

The highlights of this release are support for [Shanghai] execution specification upgrade
and implementation of EOF "v1.0". There are also big enhancements to the EVM testing tools
and infrastructure. In particular, we added the [t8n] command-line utility.

As it is tradition, the EVM performance has been improved as well.
Comparing with the previous release using the "main" benchmark suite,
the Baseline interpreter is now:

- 10–45% (mean 25%) faster for GCC builds,
- 0–19% (mean 11%) faster for Clang builds.

### Added

- **[Shanghai] support**:
  - [EIP-3651]: Warm COINBASE (testing infrastructure only).
    [#560](https://github.com/ethereum/evmone/pull/560)
  - [EIP-3860]: Limit and meter initcode.
    [#545](https://github.com/ethereum/evmone/pull/545)
  - [EIP-4895]: Beacon chain push withdrawals as operations (testing infrastructure only).
    [#614](https://github.com/ethereum/evmone/pull/614)
- **EVM Object Format "EOF v1.0"**:
  - The implementation of the revisions of [EIP-3540], [EIP-3670], [EIP-4200], [EIP-4750] and [EIP-5450]
    originally proposed for [Shanghai].
    [#563](https://github.com/ethereum/evmone/pull/563)
    [#572](https://github.com/ethereum/evmone/pull/572)
    [#594](https://github.com/ethereum/evmone/pull/594)
    [#508](https://github.com/ethereum/evmone/pull/508)
  - EOF is currently enabled in the [Cancun] revision but likely to be moved to Prague in the future.
    [#561](https://github.com/ethereum/evmone/pull/561)
  - Added `evmone-eofparse` and `evmone-eofparsefuzz` tools for testing EOF validation.
    [#568](https://github.com/ethereum/evmone/pull/568)
- Implemented [EIP-663]: Unlimited SWAP and DUP instructions (enabled in EOF).
  [#529](https://github.com/ethereum/evmone/pull/529)
- Added implementation of `evmc::Host`, **state transition** and block finalization for testing purposes.
  [#484](https://github.com/ethereum/evmone/pull/484)
  [#519](https://github.com/ethereum/evmone/pull/519)
  [#575](https://github.com/ethereum/evmone/pull/575)
  [#608](https://github.com/ethereum/evmone/pull/608)
  [#609](https://github.com/ethereum/evmone/pull/609)
- Added **[t8n]** tool `evmone-t8n`
  — a command line utility for transaction execution and state transition testing.
  It allows executing and generating tests with cooperation of [retesteth] or [execution-spec-tests].
  [#552](https://github.com/ethereum/evmone/pull/552)
  [#555](https://github.com/ethereum/evmone/pull/555)
  [#558](https://github.com/ethereum/evmone/pull/558)
  [#569](https://github.com/ethereum/evmone/pull/569)
  [#583](https://github.com/ethereum/evmone/pull/583)
  [#590](https://github.com/ethereum/evmone/pull/590)
  [#591](https://github.com/ethereum/evmone/pull/591)
  [#604](https://github.com/ethereum/evmone/pull/604)
  [#606](https://github.com/ethereum/evmone/pull/606)
  [#607](https://github.com/ethereum/evmone/pull/607)
  [#612](https://github.com/ethereum/evmone/pull/612)
- Added partial support for EVM Precompiles
  — gas cost computation and execution via _[JSON stub file](./test/state/precompiles_stub.json)_.
  [#524](https://github.com/ethereum/evmone/pull/524)
- Declarative state transition unit test suite.
  [#589](https://github.com/ethereum/evmone/pull/589)
- CMake option `EVMONE_X86_64_ARCH_LEVEL` to set the
  [x86-64 microarchitecture level](https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels).
  On Linux and Windows this is set to x86-64-v2 by default.
  [#548](https://github.com/ethereum/evmone/pull/548)

### Changed

- C++20 is now required to build evmone.
  [#502](https://github.com/ethereum/evmone/pull/502)
- Minimal tested/supported compilers versions:
  [#535](https://github.com/ethereum/evmone/pull/535)
  - GCC 11
  - Clang 13
  - XCode 13.4
  - Visual Studio 2022
  - CMake 3.16
- [EVMC] has been upgraded to version [10.1.0][EVMC 10.1.0].
  [#623](https://github.com/ethereum/evmone/pull/623)
- [intx] has been upgraded to version [0.10.0][intx 0.10.0].
  [#622](https://github.com/ethereum/evmone/pull/622)
- [ethash] has been upgraded to version [1.0.0][ethash 1.0.0].
  [#540](https://github.com/ethereum/evmone/pull/540)
- [Ethereum Execution Tests] has been upgraded to version [12.2][tests 12.2].
  [#625](https://github.com/ethereum/evmone/pull/625)
- **Baseline interpreter optimizations**:
  - Better stack overflow/underflow checks.
    [#518](https://github.com/ethereum/evmone/pull/518)
  - SWAP instructions optimization for Clang.
    [#527](https://github.com/ethereum/evmone/pull/527)
  - Pass gas counter to memory grow/check helpers by value.
    [#598](https://github.com/ethereum/evmone/pull/598)
  - Pass gas counter to instructions by value.
    [#600](https://github.com/ethereum/evmone/pull/600)
- Changes to EVM tracing:
  - Instruction trace prints `"gas"` and `"gasUsed"` as hex numbers to match geth.
    [#592](https://github.com/ethereum/evmone/pull/592)
  - C++ tracing API has separated the `gas` parameter.
    [#599](https://github.com/ethereum/evmone/pull/599)
- Improvements to the JSON State Test execution tool `evmone-statetest`:
  - Ability to load tests from multiple dirs/files.
    [#512](https://github.com/ethereum/evmone/pull/512)
  - Validate deployed EOF code before state test execution.
    [#593](https://github.com/ethereum/evmone/pull/593)
    [#601](https://github.com/ethereum/evmone/pull/601)
  - Added `--trace` command-line flag to enable EVM execution tracing.
    [#543](https://github.com/ethereum/evmone/pull/543)
  - Other improvements.
    [#556](https://github.com/ethereum/evmone/pull/556)
    [#603](https://github.com/ethereum/evmone/pull/603)
- Benchmarks (invocable by `evmone-bench`) have been migrated to
  external [evm-benchmarks] which use JSON State Test format.
  [#513](https://github.com/ethereum/evmone/pull/513)
  [#530](https://github.com/ethereum/evmone/pull/530)
- Removed dependency on `evmc::instructions`.
  [#533](https://github.com/ethereum/evmone/pull/533)
  [#534](https://github.com/ethereum/evmone/pull/534)
  [#537](https://github.com/ethereum/evmone/pull/537)

### Fixed

- Fixed calling `Tracer.notify_execution_start`.
  [#531](https://github.com/ethereum/evmone/pull/531)
- Fixed instruction tracing of EOF code.
  [#536](https://github.com/ethereum/evmone/pull/536)

### New Contributors

- **[JSzymanskiJS](https://github.com/ethereum/evmone/commits?author=JSzymanskiJS)**
  [#512](https://github.com/ethereum/evmone/pull/512)
- **[miles170](https://github.com/ethereum/evmone/commits?author=miles170)**
  [#513](https://github.com/ethereum/evmone/pull/513)
- **[rodiazet](https://github.com/ethereum/evmone/commits?author=rodiazet)**
  [#531](https://github.com/ethereum/evmone/pull/531)


## [0.9.1] — 2022-09-07

### Fixed

- Resetting gas refund counter when execution state is reused. 
  [#504](https://github.com/ethereum/evmone/pull/504)


## [0.9.0] — 2022-08-30

In this release we have been focused on improving performance of the Baseline interpreter.
The end result is that the Baseline is **26% faster** than in previous version 0.8.0
and **18% faster** than the current Advanced interpreter while having
over **8x smaller** code analysis cost. The Baseline is now the _default_ interpreter because 
it is simpler and has become better than the Advanced.

The Advanced also has got **4% faster** than in the previous version.

All numbers are from running the "main" benchmark suite
on 4.0 GHz Intel Haswell CPU, using the Clang 15 compiler.

Moreover, evmone now calculates _gas refund_ and reports it back using [EVMC 10][EVMC 10.0.0] API.

Finally, the options `O=2` and `O=0` have been replaced by `advanced`. See below for details.

### Added

- Calculation of EVM gas refunds.
  [#493](https://github.com/ethereum/evmone/pull/493)
- `PUSH0` instruction implementation ([EIP-3855]), enabled in [Shanghai].
  [#448](https://github.com/ethereum/evmone/pull/448)
  [#432](https://github.com/ethereum/evmone/pull/432)
- Experimental [EOF] validation and execution ([EIP-3540]), enabled in [Shanghai].
  [#334](https://github.com/ethereum/evmone/pull/334)
  [#366](https://github.com/ethereum/evmone/pull/366)
  [#471](https://github.com/ethereum/evmone/pull/471)
- _In progress_ State Transition execution tool for testing purposes. So far we've merged:
  - RLP encoding,
    [#463](https://github.com/ethereum/evmone/pull/463)
  - Merkle Patricia Trie root hash computing,
    [#477](https://github.com/ethereum/evmone/pull/477)
    [#478](https://github.com/ethereum/evmone/pull/478)
  - JSON State Transition Test loader.
    [#479](https://github.com/ethereum/evmone/pull/479)

### Changed

- EVMC options `O=0` (use Baseline) and `O=2` (use Advanced) have been replaced with single
  option `advanced` to use the non-default Advanced interpreter.
  [#500](https://github.com/ethereum/evmone/pull/500)
- Baseline has replaced Advanced as the default interpreter. The later can still be selected
  with the `advanced` option. Reasons are explained in the introduction.
  [#500](https://github.com/ethereum/evmone/pull/500)
- _A lot_ of changes related to the optimization of the Baseline interpreter, including
  refactoring and optimization of instructions' implementations.
- The Baseline interpreter now uses "computed goto" dispatch if supported by C++ compiler.
  The "switch" dispatch can be forced with the `cgoto=no` option.
  [#495](https://github.com/ethereum/evmone/pull/495)
- Improvements to basic block metadata placement in the Advanced interpreter.
  [#457](https://github.com/ethereum/evmone/pull/457)
  [#474](https://github.com/ethereum/evmone/pull/474)
- [EVMC] has been upgraded to version [10.0.0][EVMC 10.0.0].
  [#499](https://github.com/ethereum/evmone/pull/499)
- [intx] has been upgrade to version [0.8.0][intx 0.8.0].
  [#446](https://github.com/ethereum/evmone/pull/446)

### Removed

- `evmone-fuzzer` has removed [aleth-interpreter][Aleth] as it is not maintained
  and lacks the latest EVM features.
  [#453](https://github.com/ethereum/evmone/pull/453)


## [0.8.2] — 2021-08-26

### Fixed

- Fixed building of `evmone-standalone` static library when the `llvm-ar` tool is being used.
  [#373](https://github.com/ethereum/evmone/pull/373)
  [#374](https://github.com/ethereum/evmone/pull/374)


## [0.8.1] — 2021-08-03

### Fixed

- baseline: Fix incorrect exit after invalid jump.
  [#370](https://github.com/ethereum/evmone/pull/370)


## [0.8.0] — 2021-07-01

### Added

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
- The [Ethereum Execution Tests] upgraded to version [9.0.2][tests 9.0.2].
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
  the unmaintained [Aleth]. The [Ethereum Execution Tests] [8.0.4][tests 8.0.4] are currently being used.


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


[0.10.0]: https://github.com/ethereum/evmone/releases/tag/v0.10.0
[0.9.1]: https://github.com/ethereum/evmone/releases/tag/v0.9.1
[0.9.0]: https://github.com/ethereum/evmone/releases/tag/v0.9.0
[0.8.2]: https://github.com/ethereum/evmone/releases/tag/v0.8.2
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
[EIP-663]: https://eips.ethereum.org/EIPS/eip-663
[EIP-1884]: https://eips.ethereum.org/EIPS/eip-1884
[EIP-1344]: https://eips.ethereum.org/EIPS/eip-1344
[EIP-2200]: https://eips.ethereum.org/EIPS/eip-2200
[EIP-2929]: https://eips.ethereum.org/EIPS/eip-2929
[EIP-3155]: https://eips.ethereum.org/EIPS/eip-3155
[EIP-3198]: https://eips.ethereum.org/EIPS/eip-3198
[EIP-3540]: https://eips.ethereum.org/EIPS/eip-3540
[EIP-3651]: https://eips.ethereum.org/EIPS/eip-3651
[EIP-3670]: https://eips.ethereum.org/EIPS/eip-3670
[EIP-3855]: https://eips.ethereum.org/EIPS/eip-3855
[EIP-3860]: https://eips.ethereum.org/EIPS/eip-3860
[EIP-4200]: https://eips.ethereum.org/EIPS/eip-4200
[EIP-4750]: https://eips.ethereum.org/EIPS/eip-4750
[EIP-4895]: https://eips.ethereum.org/EIPS/eip-4895
[EIP-5450]: https://eips.ethereum.org/EIPS/eip-5450
[Spurious Dragon]: https://eips.ethereum.org/EIPS/eip-607
[Petersburg]: https://eips.ethereum.org/EIPS/eip-1716
[Istanbul]: https://eips.ethereum.org/EIPS/eip-1679
[Berlin]: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md
[London]: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/london.md
[Shanghai]: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/shanghai.md
[Cancun]: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md
[EOF]: https://notes.ethereum.org/@ipsilon/evm-object-format-overview
[EVMC]: https://github.com/ethereum/evmc
[EVMC 10.1.0]: https://github.com/ethereum/evmc/releases/tag/v10.1.0
[EVMC 10.0.0]: https://github.com/ethereum/evmc/releases/tag/v10.0.0
[EVMC 9.0.0]: https://github.com/ethereum/evmc/releases/tag/v9.0.0
[EVMC 8.0.0]: https://github.com/ethereum/evmc/releases/tag/v8.0.0
[EVMC 7.5.0]: https://github.com/ethereum/evmc/releases/tag/v7.5.0
[EVMC 7.4.0]: https://github.com/ethereum/evmc/releases/tag/v7.4.0
[EVMC 7.1.0]: https://github.com/ethereum/evmc/releases/tag/v7.1.0
[EVMC 7.0.0]: https://github.com/ethereum/evmc/releases/tag/v7.0.0
[intx]: https://github.com/chfast/intx
[intx 0.10.0]: https://github.com/chfast/intx/releases/tag/v0.10.0
[intx 0.8.0]: https://github.com/chfast/intx/releases/tag/v0.8.0
[intx 0.6.0]: https://github.com/chfast/intx/releases/tag/v0.6.0
[intx 0.5.0]: https://github.com/chfast/intx/releases/tag/v0.5.0
[ethash]: https://github.com/chfast/ethash
[ethash 0.7.0]: https://github.com/chfast/ethash/releases/tag/v0.7.0
[ethash 1.0.0]: https://github.com/chfast/ethash/releases/tag/v1.0.0
[Ethereum Execution Tests]: https://github.com/ethereum/tests
[tests 12.2]: https://github.com/ethereum/tests/releases/tag/v12.2
[tests 9.0.2]: https://github.com/ethereum/tests/releases/tag/9.0.2
[tests 8.0.4]: https://github.com/ethereum/tests/releases/tag/8.0.4
[evm-benchmarks]: https://github.com/ipsilon/evm-benchmarks
[execution-spec-tests]: https://github.com/ethereum/execution-spec-tests
[retesteth]: https://github.com/ethereum/retesteth
[Silkworm]: https://github.com/torquem-ch/silkworm
[t8n]: https://ethereum-tests.readthedocs.io/en/develop/t8ntool-ref.html
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
