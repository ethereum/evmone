// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/stdx/utility.hpp"
#include "../utils/utils.hpp"
#include "statetest.hpp"
#include <evmone/eof.hpp>
#include <nlohmann/json.hpp>

namespace evmone::test
{
namespace json = nlohmann;
using evmc::from_hex;

template <>
uint8_t from_json<uint8_t>(const json::json& j)
{
    const auto ret = std::stoul(j.get<std::string>(), nullptr, 16);
    if (ret > std::numeric_limits<uint8_t>::max())
        throw std::out_of_range("from_json<uint8_t>: value > 0xFF");

    return static_cast<uint8_t>(ret);
}

template <typename T>
static std::optional<T> integer_from_json(const json::json& j)
{
    if (j.is_number_integer())
        return j.get<T>();

    if (!j.is_string())
        return {};

    const auto s = j.get<std::string>();

    // Always load integers as unsigned and cast to the required type.
    // This will work for cases where a test case uses uint64 timestamps while we use int64.
    // TODO: Change timestamp type to uint64.
    size_t num_processed = 0;
    const auto v = static_cast<T>(std::stoull(s, &num_processed, 0));
    if (num_processed == 0 || num_processed != s.size())
        return {};
    return v;
}

template <>
int64_t from_json<int64_t>(const json::json& j)
{
    const auto v = integer_from_json<int64_t>(j);
    if (!v.has_value())
        throw std::invalid_argument("from_json<int64_t>: must be integer or string of integer");
    return *v;
}

template <>
uint64_t from_json<uint64_t>(const json::json& j)
{
    const auto v = integer_from_json<uint64_t>(j);
    if (!v.has_value())
        throw std::invalid_argument("from_json<uint64_t>: must be integer or string of integer");
    return *v;
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
    // Special case to handle "0". Required by exec-spec-tests.
    // TODO: Get rid of it.
    if (j.is_string() && (j == "0" || j == "0x0"))
        return 0x00_bytes32;
    else
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

// Based on calculateEIP1559BaseFee from ethereum/retesteth
inline uint64_t calculate_current_base_fee_eip1559(
    uint64_t parent_gas_used, uint64_t parent_gas_limit, uint64_t parent_base_fee)
{
    // TODO: Make sure that 64-bit precision is good enough.
    static constexpr auto BASE_FEE_MAX_CHANGE_DENOMINATOR = 8;
    static constexpr auto ELASTICITY_MULTIPLIER = 2;

    uint64_t base_fee = 0;

    const auto parent_gas_target = parent_gas_limit / ELASTICITY_MULTIPLIER;

    if (parent_gas_used == parent_gas_target)
        base_fee = parent_base_fee;
    else if (parent_gas_used > parent_gas_target)
    {
        const auto gas_used_delta = parent_gas_used - parent_gas_target;
        const auto formula =
            parent_base_fee * gas_used_delta / parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR;
        const auto base_fee_per_gas_delta = formula > 1 ? formula : 1;
        base_fee = parent_base_fee + base_fee_per_gas_delta;
    }
    else
    {
        const auto gas_used_delta = parent_gas_target - parent_gas_used;

        const auto base_fee_per_gas_delta_u128 =
            intx::uint128(parent_base_fee, 0) * intx::uint128(gas_used_delta, 0) /
            parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR;

        const auto base_fee_per_gas_delta = base_fee_per_gas_delta_u128[0];
        if (parent_base_fee > base_fee_per_gas_delta)
            base_fee = parent_base_fee - base_fee_per_gas_delta;
        else
            base_fee = 0;
    }
    return base_fee;
}

template <>
state::Withdrawal from_json<state::Withdrawal>(const json::json& j)
{
    return {from_json<uint64_t>(j.at("index")), from_json<uint64_t>(j.at("validatorIndex")),
        from_json<evmc::address>(j.at("address")), from_json<uint64_t>(j.at("amount"))};
}

template <>
state::BlockInfo from_json<state::BlockInfo>(const json::json& j)
{
    evmc::bytes32 prev_randao;
    int64_t current_difficulty = 0;
    int64_t parent_difficulty = 0;
    const auto prev_randao_it = j.find("currentRandom");
    const auto current_difficulty_it = j.find("currentDifficulty");
    const auto parent_difficulty_it = j.find("parentDifficulty");

    if (current_difficulty_it != j.end())
        current_difficulty = from_json<int64_t>(*current_difficulty_it);
    if (parent_difficulty_it != j.end())
        parent_difficulty = from_json<int64_t>(*parent_difficulty_it);

    // When it's not defined init it with difficulty value.
    if (prev_randao_it != j.end())
        prev_randao = from_json<bytes32>(*prev_randao_it);
    else if (current_difficulty_it != j.end())
        prev_randao = from_json<bytes32>(*current_difficulty_it);
    else if (parent_difficulty_it != j.end())
        prev_randao = from_json<bytes32>(*parent_difficulty_it);

    hash256 parent_uncle_hash;
    const auto parent_uncle_hash_it = j.find("parentUncleHash");
    if (parent_uncle_hash_it != j.end())
        parent_uncle_hash = from_json<hash256>(*parent_uncle_hash_it);

    uint64_t base_fee = 0;
    if (j.contains("currentBaseFee"))
        base_fee = from_json<uint64_t>(j.at("currentBaseFee"));
    else if (j.contains("parentBaseFee"))
    {
        base_fee = calculate_current_base_fee_eip1559(from_json<uint64_t>(j.at("parentGasUsed")),
            from_json<uint64_t>(j.at("parentGasLimit")),
            from_json<uint64_t>(j.at("parentBaseFee")));
    }

    std::vector<state::Withdrawal> withdrawals;
    if (const auto withdrawals_it = j.find("withdrawals"); withdrawals_it != j.end())
    {
        for (const auto& withdrawal : *withdrawals_it)
            withdrawals.push_back(from_json<state::Withdrawal>(withdrawal));
    }

    std::unordered_map<int64_t, hash256> block_hashes;
    if (const auto block_hashes_it = j.find("blockHashes"); block_hashes_it != j.end())
    {
        for (const auto& [j_num, j_hash] : block_hashes_it->items())
            block_hashes[from_json<int64_t>(j_num)] = from_json<hash256>(j_hash);
    }

    std::vector<state::Ommer> ommers;
    if (const auto ommers_it = j.find("ommers"); ommers_it != j.end())
    {
        for (const auto& ommer : *ommers_it)
        {
            ommers.push_back(
                {from_json<evmc::address>(ommer.at("address")), ommer.at("delta").get<uint32_t>()});
        }
    }

    int64_t parent_timestamp = 0;
    auto parent_timestamp_it = j.find("parentTimestamp");
    if (parent_timestamp_it != j.end())
        parent_timestamp = from_json<int64_t>(*parent_timestamp_it);

    uint64_t excess_blob_gas = 0;
    if (const auto it = j.find("parentExcessBlobGas"); it != j.end())
    {
        const auto parent_excess_blob_gas = from_json<uint64_t>(*it);
        const auto parent_blob_gas_used = from_json<uint64_t>(j.at("parentBlobGasUsed"));
        static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK = 0x60000;
        excess_blob_gas =
            std::max(parent_excess_blob_gas + parent_blob_gas_used, TARGET_BLOB_GAS_PER_BLOCK) -
            TARGET_BLOB_GAS_PER_BLOCK;
    }
    else if (const auto it2 = j.find("currentExcessBlobGas"); it2 != j.end())
    {
        excess_blob_gas = from_json<uint64_t>(*it2);
    }

    return state::BlockInfo{
        .number = from_json<int64_t>(j.at("currentNumber")),
        .timestamp = from_json<int64_t>(j.at("currentTimestamp")),
        .parent_timestamp = parent_timestamp,
        .gas_limit = from_json<int64_t>(j.at("currentGasLimit")),
        .coinbase = from_json<evmc::address>(j.at("currentCoinbase")),
        .difficulty = current_difficulty,
        .parent_difficulty = parent_difficulty,
        .parent_ommers_hash = parent_uncle_hash,
        .prev_randao = prev_randao,
        .parent_beacon_block_root = {},
        .base_fee = base_fee,
        .excess_blob_gas = excess_blob_gas,
        .blob_base_fee = state::compute_blob_gas_price(excess_blob_gas),
        .ommers = std::move(ommers),
        .withdrawals = std::move(withdrawals),
        .known_block_hashes = std::move(block_hashes),
    };
}

template <>
state::State from_json<state::State>(const json::json& j)
{
    state::State o;
    for (const auto& [j_addr, j_acc] : j.items())
    {
        auto& acc = o.insert(from_json<address>(j_addr),
            {.nonce = from_json<uint64_t>(j_acc.at("nonce")),
                .balance = from_json<intx::uint256>(j_acc.at("balance")),
                .code = from_json<bytes>(j_acc.at("code"))});

        if (const auto storage_it = j_acc.find("storage"); storage_it != j_acc.end())
        {
            for (const auto& [j_key, j_value] : storage_it->items())
            {
                if (const auto value = from_json<bytes32>(j_value); !is_zero(value))
                    acc.storage.insert(
                        {from_json<bytes32>(j_key), {.current = value, .original = value}});
            }
        }
    }
    return o;
}

/// Load common parts of Transaction or TestMultiTransaction.
static void from_json_tx_common(const json::json& j, state::Transaction& o)
{
    o.sender = from_json<evmc::address>(j.at("sender"));
    o.nonce = from_json<uint64_t>(j.at("nonce"));

    if (const auto to_it = j.find("to"); to_it != j.end() && !to_it->get<std::string>().empty())
        o.to = from_json<evmc::address>(*to_it);

    if (const auto gas_price_it = j.find("gasPrice"); gas_price_it != j.end())
    {
        o.type = state::Transaction::Type::legacy;
        o.max_gas_price = from_json<intx::uint256>(*gas_price_it);
        o.max_priority_gas_price = o.max_gas_price;
        if (j.contains("maxFeePerGas") || j.contains("maxPriorityFeePerGas"))
        {
            throw std::invalid_argument(
                "invalid transaction: contains both legacy and EIP-1559 fees");
        }
    }
    else
    {
        o.type = state::Transaction::Type::eip1559;
        o.max_gas_price = from_json<intx::uint256>(j.at("maxFeePerGas"));
        o.max_priority_gas_price = from_json<intx::uint256>(j.at("maxPriorityFeePerGas"));
    }

    if (const auto it = j.find("maxFeePerBlobGas"); it != j.end())
        o.max_blob_gas_price = from_json<intx::uint256>(*it);

    if (const auto it = j.find("blobVersionedHashes"); it != j.end())
    {
        o.type = state::Transaction::Type::blob;
        for (const auto& hash : *it)
            o.blob_hashes.push_back(from_json<bytes32>(hash));
    }
    else if (const auto it_initcodes = j.find("initcodes"); it_initcodes != j.end())
    {
        o.type = state::Transaction::Type::initcodes;
        for (const auto& initcode : *it_initcodes)
            o.initcodes.push_back(from_json<bytes>(initcode));
    }
}

template <>
state::Transaction from_json<state::Transaction>(const json::json& j)
{
    state::Transaction o;
    from_json_tx_common(j, o);
    if (const auto chain_id_it = j.find("chainId"); chain_id_it != j.end())
        o.chain_id = from_json<uint8_t>(*chain_id_it);

    if (const auto it = j.find("data"); it != j.end())
        o.data = from_json<bytes>(*it);
    else
        o.data = from_json<bytes>(j.at("input"));

    if (const auto it = j.find("gasLimit"); it != j.end())
        o.gas_limit = from_json<int64_t>(*it);
    else
        o.gas_limit = from_json<int64_t>(j.at("gas"));

    o.value = from_json<intx::uint256>(j.at("value"));

    if (const auto ac_it = j.find("accessList"); ac_it != j.end())
    {
        o.access_list = from_json<state::AccessList>(*ac_it);
        if (o.type == state::Transaction::Type::legacy)  // Upgrade tx type if tx has access list
            o.type = state::Transaction::Type::access_list;
    }

    if (const auto type_it = j.find("type"); type_it != j.end())
    {
        const auto infered_type = stdx::to_underlying(o.type);
        const auto type = from_json<uint8_t>(*type_it);
        if (type != infered_type)
            throw std::invalid_argument("wrong transaction type: " + std::to_string(type) +
                                        ", expected: " + std::to_string(infered_type));
    }

    o.nonce = from_json<uint64_t>(j.at("nonce"));
    o.r = from_json<intx::uint256>(j.at("r"));
    o.s = from_json<intx::uint256>(j.at("s"));
    o.v = from_json<uint8_t>(j.at("v"));

    return o;
}

static void from_json(const json::json& j, TestMultiTransaction& o)
{
    from_json_tx_common(j, o);

    for (const auto& j_data : j.at("data"))
        o.inputs.emplace_back(from_json<bytes>(j_data));

    if (const auto ac_it = j.find("accessLists"); ac_it != j.end())
    {
        for (const auto& j_access_list : *ac_it)
            o.access_lists.emplace_back(from_json<state::AccessList>(j_access_list));
        if (o.type == state::Transaction::Type::legacy)  // Upgrade tx type if tx has access lists
            o.type = state::Transaction::Type::access_list;
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
    if (!j.is_object() || j.empty())
        throw std::invalid_argument{"JSON test must be an object with single key of the test name"};

    const auto& j_t = *j.begin();  // Content is in a dict with the test name.

    o.pre_state = from_json<state::State>(j_t.at("pre"));

    o.multi_tx = j_t.at("transaction").get<TestMultiTransaction>();

    o.block = from_json<state::BlockInfo>(j_t.at("env"));

    if (const auto info_it = j_t.find("_info"); info_it != j_t.end())
    {
        if (const auto labels_it = info_it->find("labels"); labels_it != info_it->end())
        {
            for (const auto& [j_id, j_label] : labels_it->items())
                o.input_labels.emplace(from_json<uint64_t>(j_id), j_label);
        }
    }

    for (const auto& [rev_name, expectations] : j_t.at("post").items())
    {
        // TODO(c++20): Use emplace_back with aggregate initialization.
        o.cases.push_back({to_rev(rev_name),
            expectations.get<std::vector<StateTransitionTest::Case::Expectation>>()});
    }
}

StateTransitionTest load_state_test(std::istream& input)
{
    return json::json::parse(input).get<StateTransitionTest>();
}

void validate_state(const state::State& state, evmc_revision rev)
{
    for (const auto& [addr, acc] : state.get_accounts())
    {
        // TODO: Check for empty accounts after Paris.
        //       https://github.com/ethereum/tests/issues/1331
        if (is_eof_container(acc.code))
        {
            if (rev >= EVMC_PRAGUE)
            {
                if (const auto result = validate_eof(rev, acc.code);
                    result != EOFValidationError::success)
                {
                    throw std::invalid_argument(
                        "EOF container at " + hex0x(addr) +
                        " is invalid: " + std::string(get_error_message(result)));
                }
            }
            else
            {
                throw std::invalid_argument("unexpected code with EOF prefix at " + hex0x(addr));
            }
        }

        for (const auto& [key, value] : acc.storage)
        {
            if (is_zero(value.original))
            {
                throw std::invalid_argument{"account " + hex0x(addr) +
                                            " contains invalid zero-value storage entry " +
                                            hex0x(key)};
            }
        }
    }
}
}  // namespace evmone::test
