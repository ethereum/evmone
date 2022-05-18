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
    static constexpr std::string_view bigint_marker{"0x:bigint "};
    if (std::string_view{s}.substr(0, bigint_marker.size()) == bigint_marker)
        return std::numeric_limits<intx::uint256>::max();  // Fake it
    return intx::from_string<intx::uint256>(s);
}

template <>
state::AccessList from_json<state::AccessList>(const json::json& j)
{
    state::AccessList o;
    for (const auto& a : j)
    {
        o.push_back({from_json<address>(a.at("address")), {}});
        auto& storage_access_list = o.back().second;
        for (const auto& storage_key : a.at("storageKeys"))
            storage_access_list.emplace_back(from_json<hash256>(storage_key));
    }
    return o;
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
    throw std::invalid_argument{"unknown revision: " + std::string{s}};
}
}  // namespace

static void from_json(const json::json& j, TestMultiTransaction& o)
{
    if (j.contains("gasPrice"))
    {
        o.kind = state::Transaction::Kind::legacy;
        o.max_gas_price = from_json<intx::uint256>(j["gasPrice"]);
        o.max_priority_gas_price = o.max_gas_price;
    }
    else
    {
        o.kind = state::Transaction::Kind::eip1559;
        o.max_gas_price = from_json<intx::uint256>(j["maxFeePerGas"]);
        o.max_priority_gas_price = from_json<intx::uint256>(j["maxPriorityFeePerGas"]);
    }
    o.nonce = from_json<uint64_t>(j["nonce"]);
    o.sender = from_json<evmc::address>(j["sender"]);
    if (!j["to"].get<std::string>().empty())
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
    o.input = j["data"].get<size_t>();
    o.gas_limit = j["gas"].get<size_t>();
    o.value = j["value"].get<size_t>();
}

static void from_json(const json::json& j, TestCase::Case& o)
{
    o.indexes = j["indexes"].get<TestMultiTransaction::Indexes>();
    o.state_hash = from_json<hash256>(j["hash"]);
    o.logs_hash = from_json<hash256>(j["logs"]);
    o.exception = j.contains("expectException");
}

static void from_json(const json::json& j, StateTransitionTest& o)
{
    const auto& j_t = j.begin().value();  // Content is in a dict with the test name.

    for (const auto& [j_addr, j_acc] : j_t["pre"].items())
    {
        const auto addr = from_json<address>(j_addr);
        auto& acc = o.pre_state.create(addr);
        acc.balance = from_json<intx::uint256>(j_acc["balance"]);
        acc.nonce = from_json<uint64_t>(j_acc["nonce"]);
        acc.code = from_json<bytes>(j_acc["code"]);

        for (const auto& [j_key, j_value] : j_acc["storage"].items())
        {
            auto& slot = acc.storage[from_json<bytes32>(j_key)];
            const auto value = from_json<bytes32>(j_value);
            slot.original = value;
            slot.current = value;
        }
    }

    o.multi_tx = j_t["transaction"].get<TestMultiTransaction>();

    const auto& env = j_t["env"];
    o.block.gas_limit = from_json<int64_t>(env["currentGasLimit"]);
    o.block.coinbase = from_json<evmc::address>(env["currentCoinbase"]);
    o.block.base_fee = from_json<uint64_t>(env["currentBaseFee"]);
    o.block.difficulty = from_json<evmc::uint256be>(env["currentDifficulty"]);
    o.block.number = from_json<int64_t>(env["currentNumber"]);
    o.block.timestamp = from_json<int64_t>(env["currentTimestamp"]);

    // TODO: Chain ID is expected to be 1.
    o.block.chain_id = {};
    o.block.chain_id.bytes[31] = 1;

    for (const auto& [rev_name, posts] : j_t["post"].items())
        o.cases.push_back({to_rev(rev_name), posts.get<std::vector<TestCase::Case>>()});
}

StateTransitionTest load_state_test(const fs::path& test_file)
{
    return json::json::parse(std::ifstream{test_file}).get<StateTransitionTest>();
}
}  // namespace evmone::test
