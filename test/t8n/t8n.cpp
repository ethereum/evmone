// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/errors.hpp"
#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "../statetest/statetest.hpp"
#include <evmone/evmone.h>
#include <evmone/version.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

namespace fs = std::filesystem;
namespace json = nlohmann;
using namespace evmone;
using namespace evmone::test;
using namespace std::literals;

namespace
{
using namespace intx;

int64_t get_bomb_delay(evmc_revision rev)
{
    switch (rev)
    {
    case EVMC_BYZANTIUM:
        return 3000000;
    case EVMC_CONSTANTINOPLE:
    case EVMC_PETERSBURG:
    case EVMC_ISTANBUL:
        return 5000000;
    case EVMC_BERLIN:
        return 9000000;
    case EVMC_LONDON:
        return 9700000;
    default:
        throw std::runtime_error("get_bomb_delay: Wrong rev");
    }
}

int64_t calc_difficulty(const int64_t& parent_difficulty, const hash256& parent_uncle_hash,
    const int64_t& parent_timestamp, const int64_t& current_timestamp, const int64_t& block_num,
    evmc_revision rev)
{
    if (rev >= EVMC_PARIS)
        return 0;

    // TODO: Implement for older revisions
    if (rev < EVMC_BYZANTIUM)
        return 0x020000;

    static constexpr auto min_difficulty = int64_t{1} << 17;

    const auto kappa = get_bomb_delay(rev);

    const auto H_i_prime = kappa >= block_num ? 0 : block_num - kappa;

    const auto p = (H_i_prime / 100000) - 2;
    assert(p < 63);

    const auto epsilon = p < 0 ? 0 : int64_t{1} << p;

    static const hash256 empty_uncle_hash =
        0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32;

    const auto y = parent_uncle_hash != empty_uncle_hash ? 2 : 1;

    const auto sigma_2 = std::max(y - (current_timestamp - parent_timestamp) / 9, int64_t{-99});

    const int64_t x = parent_difficulty / 2048;

    return std::max(min_difficulty, (int64_t)parent_difficulty + x * sigma_2 + epsilon);
}
}  // namespace

int main(int argc, const char* argv[])
{
    evmc_revision rev = {};
    fs::path alloc_file;
    fs::path env_file;
    fs::path txs_file;
    fs::path output_dir;
    fs::path output_result_file;
    fs::path output_alloc_file;
    fs::path output_body_file;
    std::optional<uint64_t> block_reward;
    uint64_t chain_id = 0;

    try
    {
        for (int i = 0; i < argc; ++i)
        {
            const std::string_view arg{argv[i]};

            if (arg == "-v")
            {
                std::cout << "evmone-t8n " EVMONE_VERSION "\n";
                return 0;
            }
            if (arg == "--state.fork" && ++i < argc)
                rev = evmone::test::to_rev(argv[i]);
            else if (arg == "--input.alloc" && ++i < argc)
                alloc_file = argv[i];
            else if (arg == "--input.env" && ++i < argc)
                env_file = argv[i];
            else if (arg == "--input.txs" && ++i < argc)
                txs_file = argv[i];
            else if (arg == "--output.basedir" && ++i < argc)
                output_dir = argv[i];
            else if (arg == "--output.result" && ++i < argc)
                output_result_file = argv[i];
            else if (arg == "--output.alloc" && ++i < argc)
                output_alloc_file = argv[i];
            else if (arg == "--state.reward" && ++i < argc && argv[i] != "-1"sv)
                block_reward = intx::from_string<uint64_t>(argv[i]);
            else if (arg == "--state.chainid" && ++i < argc)
                chain_id = intx::from_string<uint64_t>(argv[i]);
            else if (arg == "--output.body" && ++i < argc)
                output_body_file = argv[i];
        }

        state::BlockInfo block;
        state::State state;

        if (!alloc_file.empty())
        {
            const auto j = json::json::parse(std::ifstream{alloc_file}, nullptr, false);
            state = test::from_json<state::State>(j);
        }
        if (!env_file.empty())
        {
            const auto j = json::json::parse(std::ifstream{env_file});
            block = test::from_json<state::BlockInfo>(j);
        }

        json::json j_result;

        // Difficulty was received from upstream. No need to calc
        if (block.current_difficulty != 0)
            j_result["currentDifficulty"] = hex0x(block.current_difficulty);
        else
        {
            if (rev >= EVMC_SHANGHAI)
                j_result["currentDifficulty"] = nullptr;
            else
            {
                const auto current_difficulty =
                    calc_difficulty(block.parent_difficulty, block.parent_uncle_hash,
                        block.parent_timestamp, block.timestamp, block.number, rev);

                j_result["currentDifficulty"] = hex0x(current_difficulty);
                block.current_difficulty = current_difficulty;

                // Override prev_randao with difficulty (swap bytes to BE) pre Merge
                if (rev < EVMC_PARIS)
                {
                    std::memset(block.prev_randao.bytes, 0, 32);
                    const auto s = sizeof(current_difficulty);
                    const auto diff_ptr = reinterpret_cast<const uint8_t*>(&current_difficulty);
                    for (size_t i = 0; i < s; ++i)
                        block.prev_randao.bytes[24 + i] = diff_ptr[s - 1 - i];
                }
            }
        };

        j_result["currentBaseFee"] = hex0x(block.base_fee);

        int64_t cumulative_gas_used = 0;
        std::vector<state::Transaction> transactions;
        std::vector<state::TransactionReceipt> receipts;
        int64_t remaining_gas = block.gas_limit;

        // Parse and execute transactions
        if (!txs_file.empty())
        {
            const auto j_txs = json::json::parse(std::ifstream{txs_file});

            evmc::VM vm{evmc_create_evmone(), {{"O", "0"}}};

            std::vector<state::Log> txs_logs;

            if (j_txs.is_array())
            {
                j_result["receipts"] = json::json::array();
                j_result["rejected"] = json::json::array();

                for (size_t i = 0; i < j_txs.size(); ++i)
                {
                    auto tx = test::from_json<state::Transaction>(j_txs[i]);
                    tx.chain_id = chain_id;

                    const auto computed_tx_hash = keccak256(rlp::encode(tx));

                    if (remaining_gas < tx.gas_limit)
                    {
                        json::json j_rejected_tx;
                        j_rejected_tx["hash"] = hex0x(computed_tx_hash);
                        j_rejected_tx["index"] = i;
                        j_rejected_tx["error"] =
                            make_error_code(state::ErrorCode::GAS_LIMIT_REACHED).message();
                        j_result["rejected"].push_back(j_rejected_tx);
                        continue;
                    }

                    auto sender_acc_ptr = state.find(tx.sender);
                    if (sender_acc_ptr == nullptr)
                    {
                        // It's possible to send tx from non-existent account before London fork.
                        // TODO: This should be handled in `validate_transaction` but it requires
                        // bigger change.
                        if (rev < EVMC_LONDON && tx.max_gas_price == 0)
                            state.touch(tx.sender);
                        else
                        {
                            json::json j_rejected_tx;
                            j_rejected_tx["hash"] = hex0x(computed_tx_hash);
                            j_rejected_tx["index"] = i;
                            j_rejected_tx["error"] =
                                make_error_code(state::ErrorCode::INSUFFICIENT_FUNDS).message();
                            j_result["rejected"].push_back(j_rejected_tx);
                            continue;
                        }
                    }

                    if (state.get(tx.sender).nonce < tx.nonce)
                    {
                        json::json j_rejected_tx;
                        j_rejected_tx["hash"] = hex0x(computed_tx_hash);
                        j_rejected_tx["index"] = i;
                        // TODO: Add error code to state::ErrorCode
                        j_rejected_tx["error"] = "nonce too high";
                        j_result["rejected"].push_back(j_rejected_tx);
                        continue;
                    }

                    if (state.get(tx.sender).nonce > tx.nonce)
                    {
                        json::json j_rejected_tx;
                        j_rejected_tx["hash"] = hex0x(computed_tx_hash);
                        j_rejected_tx["index"] = i;
                        // TODO: Add error code to state::ErrorCode
                        j_rejected_tx["error"] = "nonce too low";
                        j_result["rejected"].push_back(j_rejected_tx);
                        continue;
                    }

                    auto res = state::transition(state, block, tx, rev, vm);

                    if (j_txs[i].contains("hash"))
                    {
                        const auto loaded_tx_hash_opt =
                            evmc::from_hex<bytes32>(j_txs[i]["hash"].get<std::string>());

                        if (loaded_tx_hash_opt != computed_tx_hash)
                            throw std::logic_error("transaction hash mismatched: computed " +
                                                   hex0x(computed_tx_hash) + ", expected " +
                                                   hex0x(loaded_tx_hash_opt.value()));
                    }

                    if (holds_alternative<std::error_code>(res))
                    {
                        const auto ec = std::get<std::error_code>(res);
                        json::json j_rejected_tx;
                        j_rejected_tx["hash"] = hex0x(computed_tx_hash);
                        j_rejected_tx["index"] = i;
                        j_rejected_tx["error"] = ec.message();
                        j_result["rejected"].push_back(j_rejected_tx);
                    }
                    else
                    {
                        auto& receipt = get<state::TransactionReceipt>(res);

                        const auto& tx_logs = receipt.logs;

                        txs_logs.insert(txs_logs.end(), tx_logs.begin(), tx_logs.end());
                        auto& j_receipt = j_result["receipts"][j_result["receipts"].size()];

                        j_receipt["transactionHash"] = hex0x(computed_tx_hash);
                        j_receipt["gasUsed"] = hex0x(static_cast<uint64_t>(receipt.gas_used));
                        cumulative_gas_used += receipt.gas_used;
                        receipt.cumulative_gas_used = cumulative_gas_used;
                        if (rev < EVMC_BYZANTIUM)
                            receipt.post_state = state::mpt_hash(state.get_accounts());
                        j_receipt["cumulativeGasUsed"] = hex0x(cumulative_gas_used);

                        j_receipt["blockHash"] = hex0x(bytes32{});
                        j_receipt["contractAddress"] = hex0x(address{});
                        j_receipt["logsBloom"] = hex0x(receipt.logs_bloom_filter);
                        j_receipt["logs"] = json::json::array();  // FIXME: Add to_json<state:Log>
                        j_receipt["root"] = "";
                        j_receipt["status"] = "0x1";
                        j_receipt["transactionIndex"] = hex0x(i);
                        transactions.emplace_back(std::move(tx));
                        remaining_gas -= receipt.gas_used;
                        receipts.emplace_back(std::move(receipt));
                    }

                    for (auto& acc : state.get_accounts())
                    {
                        acc.second.access_status = EVMC_ACCESS_COLD;
                        for (auto& [_, val] : acc.second.storage)
                        {
                            val.access_status = EVMC_ACCESS_COLD;
                            val.original = val.current;
                        }
                    }
                }
            }

            state::finalize(
                state, rev, block.coinbase, block_reward, block.withdrawals, block.ommers);

            j_result["logsHash"] = hex0x(logs_hash(txs_logs));
            j_result["stateRoot"] = hex0x(state::mpt_hash(state.get_accounts()));
        }

        j_result["logsBloom"] = hex0x(compute_bloom_filter(receipts));
        j_result["receiptsRoot"] = hex0x(state::mpt_hash(receipts));
        j_result["txRoot"] = hex0x(state::mpt_hash(transactions));
        j_result["gasUsed"] = hex0x(cumulative_gas_used);

        std::ofstream{output_dir / output_result_file} << std::setw(2) << j_result;

        // Print out current state to outAlloc file
        json::json j_alloc;
        for (const auto& [addr, acc] : state.get_accounts())
        {
            j_alloc[hex0x(addr)]["nonce"] = hex0x(acc.nonce);
            for (const auto& [key, val] : acc.storage)
                if (!is_zero(val.current))
                    j_alloc[hex0x(addr)]["storage"][hex0x(key)] = hex0x(val.current);

            j_alloc[hex0x(addr)]["code"] = hex0x(bytes_view(acc.code.data(), acc.code.size()));
            j_alloc[hex0x(addr)]["balance"] = hex0x(acc.balance);
        }

        std::ofstream{output_dir / output_alloc_file} << std::setw(2) << j_alloc;

        if (!output_body_file.empty())
            std::ofstream{output_dir / output_body_file} << hex0x(rlp::encode(transactions));
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
