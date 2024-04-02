// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <benchmark/benchmark.h>
#include <state/precompiles.hpp>
#include <state/precompiles_internal.hpp>
#include <array>
#include <memory>

#ifdef EVMONE_PRECOMPILES_SILKPRE
#include <state/precompiles_silkpre.hpp>
#endif

namespace
{
using evmc::bytes;
using namespace evmone::state;

using ExecuteFn = ExecutionResult(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

template <PrecompileId>
constexpr auto analyze = 0;
template <>
constexpr auto analyze<PrecompileId::identity> = identity_analyze;
template <>
constexpr auto analyze<PrecompileId::ecrecover> = ecrecover_analyze;
template <>
constexpr auto analyze<PrecompileId::ecadd> = ecadd_analyze;
template <>
constexpr auto analyze<PrecompileId::ecmul> = ecmul_analyze;

template <PrecompileId>
const inline std::array inputs{0};

template <>
const inline std::array inputs<PrecompileId::identity>{
    bytes(4096, 0),
    bytes(4096, 1),
};

template <>
const inline std::array inputs<PrecompileId::ecrecover>{
    "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
    "000000000000000000000000000000000000000000000000000000000000001c"
    "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
    "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"_hex,

    // Inputs from https://etherscan.io/block/19570693
    "e6a825e35ed9be084a71892d40a03353bcc64daf121816aebb219e3a1adadee3000000000000000000000000000000000000000000000000000000000000001c16799fd127010cc658053f838ba1dbcf49274fe97d14da1c08456c917d303ad4495b97615ae683e5677714e1aa5470d2d5e95f50781cee24d12e5972b853a4be"_hex,
    "e37c09431f6725ecb8de43e77fa48a598d6dcaee19dbdd0782a56bb5d8d76f1b000000000000000000000000000000000000000000000000000000000000001cd1507bb892a41f02648e61ab306c7acc7efc50669bab3bbb179e4f21386cab5a72c3f4b47f12b7a42dec6e220792b8b7f7c2aefa9e57869d165be54061d38d37"_hex,
    "06cfd18cbba471f873110ce951f8709243ad4ee3963c0f37ca748fd8f4cb277d000000000000000000000000000000000000000000000000000000000000001c5e4a4eafc75a38761f986807a7c3c3ce3dc6d8d1b54e77e0d8f61550cb145f5609d82baa98f5affc6c1fa92da7df6bfd957c23dbaa80c43069ddd31de4b06b50"_hex,
    "ad11ccc6f37519a248f72617eb6895db5227816ecc02ffb04d7f3ead7c68c9c5000000000000000000000000000000000000000000000000000000000000001cbec7fc01246483c331848dca2435ef566c405f49c80773ed1e37c7d8e5f9763c014f06796c5f2eb28799a7d1b933e420e0a8179a7f041f7b177bb749887e3fdb"_hex,
    "845f0b1cab4c6780c61f88cd8018646af7d92f513b8478290ad607ec2c81699b000000000000000000000000000000000000000000000000000000000000001c190b2d1d6152613f92fa9406825206ea21290e4cf61e5729098d35fdf5779d4d4e008b79b927f35879c4a05444113857b0073bf336dfa0ed647809599e6f682d"_hex,
    "09b985f366a070978c1871df5d78cf890c8a51417c5a4aeaf6019a25bc6478be000000000000000000000000000000000000000000000000000000000000001bb6d464798c025aacffd1a56e0643a1ac29f6ed62f282c2e5b13bc0bbec08647c299cfa2e7c295fa7387856eedb34a94a30728fe96f6caf3c5e02c6ce0467ec3f"_hex,
    "9d160608ad1a2d3c0f9ee91b566a0f63cdd6297b255b7860485dc80915b6edd1000000000000000000000000000000000000000000000000000000000000001cab06c8d09cc508cd173b7c1943fe76b307dfd1472eac56455ad820a17b7748f87874cb1337d734eb8497f7c5b2ae78289a8806f636382140872ba414ba7b2cef"_hex,
    "c866f7d081b5ed51c07478c05950c6d49b57f9dc7e9517f2a49235dffad87ff9000000000000000000000000000000000000000000000000000000000000001b8ac1b5ea65ca74923e5d55a36649775fd4a6383a43625ebe72e80cffab2e73cc71fe84fa6b92785ccf0cb47703f6978d02199027c893e2e578d4a3b756f8a60b"_hex,
    "c866f7d081b5ed51c07478c05950c6d49b57f9dc7e9517f2a49235dffad87ff9000000000000000000000000000000000000000000000000000000000000001cf584733b44d6a4997ffb9cd2c55ad194fa105f99fb9a02265c4b02a1ab987ea93c83271a5023cda2d536fcb57676a4029c62fab694d6defd997939d0eb738ca8"_hex,

};

template <>
const inline std::array inputs<PrecompileId::ecadd>{
    "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
    "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
    "1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc286"
    "0217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4"_hex,

    // Inputs from
    // https://etherscan.io/tx/0xf1d290f8a30e84953e40f32b442f4af4d947ddc88cb9e66f1e551f82d8479e2d
    "2aee4c4a210fe1d6dd0c58e82fa8a8ebb8d6ccd57925d6c719240e7a61aff514232667094a59014c57bf0ad6a220bf66ca1e6ab8b4135fa932bffaba7dc9ac212a2652ced6e8fbaa735ba18f3851e8ef8ece83b2c7f685516eb1eb66860c82eb02840447bfa6500e7cb5532a37b89dfea32159a2769b1ab23d56a95ccfa76174"_hex,
    "0bd35c81c7113a12eabec37f18750aa99294710f22e57da632212a063f59d27a03cb8a97e16ee905fcb2e8c5a9ae9b97b6a3c20d76ebc46b7949673e1c8f40b507524717221895c6f8c667f0b0f9bba8808c1f5e2b19860619921b5ccd70e4e5032a0a201c3e477d68cddf5e26d95ba03fb6dc7cac53e17e2e8fa39267507e48"_hex,
    "0c359809f64010752fe9cde56bee5c6e98d3b362dad9c6e27983a289d7fdec6a10980910c6c33e2b3558464b76f7ce0626f951382ec370c9d92d2828d856731c1d37ba3d0f2cea2251f41a83abf667100a32c090fb5067d42b447f4559398aef07cf5d8560237e4dd19da27b3b49e5e669823375654845561f2108ef4103a574"_hex,
    "1af3c46848da0a5fbeae786b72e49f604ccd2c119d17cd46e516f6534b6075a906c3525efa7be813d47fd339faf5ff0e99adcc71c56a545681820441a3f4a1b922754034f74195e95a897f3570e0fda11e21a39081683528aab029bbdd6c5e230e0ea7e78b3ffaf0d45b3e6169515109292541acf2db63deecd198231f7819b2"_hex,
    "2d518024c07730b00e5f0252e479062b235759fca26e0460a40cfa4816be56af13a98be139f51ea9c6f1a93877056a7efcf89310f33022922c71263791fc107d16f6c6cd86354c8b06edca713969b8c30c7a93f1215e2c99bd28bc59f8b8186b230807cb63532426c0c2d1e13b0c8bef1da721eabc333888d4c6d6ff1a2e513e"_hex,
    "135b515087f247e764f5ee5af75aa52568e34a5738594175bddd43b6f332beea0d70aa546b5f89b5a626f2c97a616f83e0f29722678afed431f3a4abd589c0b42be33cd0bd8ba0e523bd7dd03706154a9709162024a776ee39cacfbcdcf264b523d77a67e344cde7785449d3350ec89e4fd5eb8aad7178f38d824d6113c594c0"_hex,
    "02548a1e93c0c6f79894c37384b9aa26770f31a675920542b5974b400c88f5dc20b5de975ed6c5d749d3555e490b7f8d2d8465b0f322a2b6a9e0679fde711cc80091961eb0f7f63b9357cfed46c61eddbc9a88fc58958461d911e1c5cb9750940506e465f95fde47460eb8fdd060e8ae89c06f665264657266c8543d7de4d3df"_hex,
    "1b1c30a53bce3f8304f27e460305daa9ee811f9de9ab7aa7f1e69a260d64c0c52e9add32cc1f0266381fe46712fac4f2052f0348d2ff202085540111fd2cd1dd209227f4a682645e784055c717d3f1dfa203f2b26096ac700cfc55082519a999064db2c23bdffe9356ba02520baef6fb898333c5c61cdcf7efc2212ed7cb070a"_hex,
    "15fe6f9e26be9c6851f4dceb593c3c3eddccf67abd05e3cba7e816c184c1650a262e4d9cee7dc9c35dcef7ef71d754179d2d2c8a9870b22201a27fed4c137d9b24ce9cd464b722e82eb266cce2be72a00e9f72eb9ea1936e9094b1ba6848a3792ff2346d6546026fe1be4f94416008247512cae8b110c2e06b58db4cb4355117"_hex,
};

template <>
const inline std::array inputs<PrecompileId::ecmul>{
    "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
    "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
    "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3"_hex,

    // Inputs from
    // https://etherscan.io/tx/0xc51e63b391ffddeddf6a797dec9329d2319cff4358989a0e8c41d58968ed8c3d
    "028f9d01bc0cb29ed29374f2e1317da679c7aafdec345db14fa3cc7b7aef3bfe1e7f063cfe3939fe829c6305471a7ecee3a1d414fd1564da6a2435fe7a40dd1f102e3dc989d704b6e15d937f543b5f434326f676ba42dc38cab2a6b531e63c86"_hex,
    "27c865075b86f234c03f92aca6cdea284c5f74db3631795351602c32ffe35e052ca0622cb684b6d03ad8ce2b33e4b607be11dacdd231d3ab068365782988dfe5102e3dc989d704b6e15d937f543b5f434326f676ba42dc38cab2a6b531e63c86"_hex,
    "115ff91c1ff2ec322468e4b55631506f15e0c911c8cbec4fd60e72245836f44b0db5de38601f262bded24fc593c1d15412eec6c3f7fdd1c691befc70fd89c9d916a872d9b0faa63cfacef41a7b0968954386bf94a3b86794a781b4aaa0d296d9"_hex,
    "00b8b470c37deeeab63eed4d8374c4bf000a0be91319a4bb144a87a80732bda904ea9ca099d607fcb70678ac3243175c455abe00ac40a2a2c0cd7ee67b2d946315816eec3322d435e2924f2e87c4a68aa13b79aab0fde90a91bbfb736459f896"_hex,
    "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020fc9202d44e2bf33f6b4a67e111504852a3a7bf361194f69afa319f8423d703f"_hex,
    "0e4fdac80cf8f87fe27488e0a398e94aaafb93f41d3623c66e10dc306f9ff3a60135a67a4dfb05a35b766b3bbca81b3afe06e823859d52c29f7203615b565c5b17d6661525677e78137f0e34bdbbeec136c1d64642493e6e2825f4d8970e98a2"_hex,
    "00c8a00b8ce94341d4ebf9abe08b5c87ea4d84dc04138a24ceefe0b9c78c4d95067172bf6abf504bbfd5652d643725e79306075513bf5161c3d64b9465964598286e7ccbf31089e0df224914b92a9a0792e323b1f55684c1aa9f7646a62fb3f2"_hex,
    "2d56bbb88255cf631060fa06f154fde7bae56510d6caaec5a0bbc22f252d7aca21e9f7e4584b24a4f105b81de76887052deed89fdce114e161d7e7178213ca0b1d102fb0fde27c3d513d530d25a84ec81d410f89c54c3d66ba4689940ce91dea"_hex,
    "30543adffffd27f2c512df127e6bbf0463986e439ba55bbd668ca5ae649c3de71525e19d26d342eaa4201d3311cbea20aea70c6293823d58f69bc154a672dd7a18089d4e577b2312bc6b0fdf414b55a27f85eda857c40ccbf6aee4eda308b6ee"_hex,
};

template <PrecompileId Id, ExecuteFn Fn>
void precompile(benchmark::State& state)
{
    int64_t batch_gas_cost = 0;
    size_t max_output_size = 0;
    for (const auto& input : inputs<Id>)
    {
        const auto r = analyze<Id>(input, EVMC_LATEST_STABLE_REVISION);
        batch_gas_cost += r.gas_cost;
        max_output_size = std::max(max_output_size, r.max_output_size);
    }
    const auto output = std::make_unique_for_overwrite<uint8_t[]>(max_output_size);


    int64_t total_gas_used = 0;
    while (state.KeepRunningBatch(inputs<Id>.size()))
    {
        for (const auto& input : inputs<Id>)
        {
            const auto [status, _] = Fn(input.data(), input.size(), output.get(), max_output_size);
            if (status != EVMC_SUCCESS) [[unlikely]]
                return state.SkipWithError("invalid result");
        }
        total_gas_used += batch_gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(batch_gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}

BENCHMARK_TEMPLATE(precompile, PrecompileId::identity, identity_execute);

namespace bench_ecrecovery
{
constexpr auto evmmax_cpp = ecrecover_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecrecover, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libsecp256k1 = silkpre_ecrecover_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecrecover, libsecp256k1);
#endif
}  // namespace bench_ecrecovery

namespace bench_ecadd
{
constexpr auto evmmax_cpp = ecadd_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecadd, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libff = silkpre_ecadd_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecadd, libff);
#endif
}  // namespace bench_ecadd

namespace bench_ecmul
{
constexpr auto evmmax_cpp = ecmul_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecmul, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libff = silkpre_ecmul_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecmul, libff);
#endif
}  // namespace bench_ecmul

}  // namespace

BENCHMARK_MAIN();
