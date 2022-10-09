// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

namespace evmone::test
{
namespace json = nlohmann;
using evmc::from_hex;

namespace
{
template <typename T>
T from_json(const json::json& j) = delete;

template <>
int64_t from_json<int64_t>(const json::json& j)
{
    return static_cast<int64_t>(std::stoll(j.get<std::string>(), nullptr, 16));
}

template <>
uint64_t from_json<uint64_t>(const json::json& j)
{
    return static_cast<uint64_t>(std::stoull(j.get<std::string>(), nullptr, 16));
}

template <>
bytes from_json<bytes>(const json::json& j)
{
    return from_hex(j.get<std::string>()).value();
}

template <>
address from_json<address>(const json::json& j)
{
    return evmc::from_hex<address>(j.get<std::string>()).value();
}

template <>
hash256 from_json<hash256>(const json::json& j)
{
    return evmc::from_hex<hash256>(j.get<std::string>()).value();
}

template <>
intx::uint256 from_json<intx::uint256>(const json::json& j)
{
    const auto s = j.get<std::string>();
    if (s.starts_with("0x:bigint "))
        return std::numeric_limits<intx::uint256>::max();  // Fake it
    return intx::from_string<intx::uint256>(s);
}

template <>
state::AccessList from_json<state::AccessList>(const json::json& j)
{
    state::AccessList o;
    for (const auto& a : j)
    {
        std::vector<bytes32> storage_access_list;
        for (const auto& storage_key : a.at("storageKeys"))
            storage_access_list.emplace_back(from_json<bytes32>(storage_key));
        o.emplace_back(from_json<address>(a.at("address")), std::move(storage_access_list));
    }
    return o;
}

template <>
state::BlockInfo from_json<state::BlockInfo>(const json::json& j)
{
    const auto prev_randao_it = j.find("currentRandom");
    return {
        from_json<int64_t>(j.at("currentNumber")),
        from_json<int64_t>(j.at("currentTimestamp")),
        from_json<int64_t>(j.at("currentGasLimit")),
        from_json<evmc::address>(j.at("currentCoinbase")),
        from_json<evmc::bytes32>(
            (prev_randao_it != j.end()) ? *prev_randao_it : j.at("currentDifficulty")),
        from_json<uint64_t>(j.value("currentBaseFee", std::string{"0"})),
    };
}

evmc_revision to_rev(std::string_view s)
{
    if (s == "Frontier")
        return EVMC_FRONTIER;
    if (s == "Homestead")
        return EVMC_HOMESTEAD;
    if (s == "EIP150")
        return EVMC_TANGERINE_WHISTLE;
    if (s == "EIP158")
        return EVMC_SPURIOUS_DRAGON;
    if (s == "Byzantium")
        return EVMC_BYZANTIUM;
    if (s == "Constantinople")
        return EVMC_CONSTANTINOPLE;
    if (s == "ConstantinopleFix")
        return EVMC_PETERSBURG;
    if (s == "Istanbul")
        return EVMC_ISTANBUL;
    if (s == "Berlin")
        return EVMC_BERLIN;
    if (s == "London")
        return EVMC_LONDON;
    if (s == "Merge")
        return EVMC_PARIS;
    if (s == "London+3540+3670")
        return EVMC_SHANGHAI;
    throw std::invalid_argument{"unknown revision: " + std::string{s}};
}
}  // namespace

static void from_json(const json::json& j, TestMultiTransaction& o)
{
    if (j.contains("gasPrice"))
    {
        o.kind = state::Transaction::Kind::legacy;
        o.max_gas_price = from_json<intx::uint256>(j.at("gasPrice"));
        o.max_priority_gas_price = o.max_gas_price;
    }
    else
    {
        o.kind = state::Transaction::Kind::eip1559;
        o.max_gas_price = from_json<intx::uint256>(j.at("maxFeePerGas"));
        o.max_priority_gas_price = from_json<intx::uint256>(j.at("maxPriorityFeePerGas"));
    }
    o.sender = from_json<evmc::address>(j.at("sender"));
    if (!j.at("to").get<std::string>().empty())
        o.to = from_json<evmc::address>(j["to"]);

    for (const auto& j_data : j.at("data"))
        o.inputs.emplace_back(from_json<bytes>(j_data));

    if (j.contains("accessLists"))
    {
        for (const auto& j_access_list : j["accessLists"])
            o.access_lists.emplace_back(from_json<state::AccessList>(j_access_list));
    }

    for (const auto& j_gas_limit : j.at("gasLimit"))
        o.gas_limits.emplace_back(from_json<int64_t>(j_gas_limit));

    for (const auto& j_value : j.at("value"))
        o.values.emplace_back(from_json<intx::uint256>(j_value));
}

static void from_json(const json::json& j, TestMultiTransaction::Indexes& o)
{
    o.input = j.at("data").get<size_t>();
    o.gas_limit = j.at("gas").get<size_t>();
    o.value = j.at("value").get<size_t>();
}

static void from_json(const json::json& j, StateTransitionTest::Case::Expectation& o)
{
    o.indexes = j.at("indexes").get<TestMultiTransaction::Indexes>();
    o.state_hash = from_json<hash256>(j.at("hash"));
    o.logs_hash = from_json<hash256>(j.at("logs"));
    o.exception = j.contains("expectException");
}

static void from_json(const json::json& j, StateTransitionTest& o)
{
    const auto& j_t = j.begin().value();  // Content is in a dict with the test name.

    for (const auto& [j_addr, j_acc] : j_t.at("pre").items())
    {
        auto& acc = o.pre_state.insert(from_json<address>(j_addr),
            {.nonce = from_json<uint64_t>(j_acc.at("nonce")),
                .balance = from_json<intx::uint256>(j_acc.at("balance")),
                .code = from_json<bytes>(j_acc.at("code"))});

        for (const auto& [j_key, j_value] : j_acc.at("storage").items())
        {
            const auto value = from_json<bytes32>(j_value);
            acc.storage.insert({from_json<bytes32>(j_key), {.current = value, .original = value}});
        }
    }

    o.multi_tx = j_t.at("transaction").get<TestMultiTransaction>();

    o.block = from_json<state::BlockInfo>(j_t.at("env"));

    if (const auto& info = j_t.at("_info"); info.contains("labels"))
    {
        for (const auto& [j_id, j_label] : info.at("labels").items())
            o.input_labels.emplace(from_json<uint64_t>(j_id), j_label);
    }

    for (const auto& [rev_name, expectations] : j_t.at("post").items())
    {
        // TODO(c++20): Use emplace_back with aggregate initialization.
        o.cases.push_back({to_rev(rev_name),
            expectations.get<std::vector<StateTransitionTest::Case::Expectation>>()});
    }
}

StateTransitionTest load_state_test(const fs::path& test_file)
{
    return json::json::parse(std::ifstream{test_file}).get<StateTransitionTest>();
}
}  // namespace evmone::test
