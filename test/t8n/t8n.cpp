// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "../statetest/statetest.hpp"
#include <evmone/evmone.h>
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

static const auto NULL_HEXSTRING_256 = "0x" + std::string(512, '0');
static const auto NULL_HEXSTRING_32 = "0x" + std::string(64, '0');
static const auto NULL_HEXSTRING_20 = "0x" + std::string(40, '0');

int main(int argc, const char* argv[])
{
    evmc_revision rev = {};
    fs::path alloc_file;
    fs::path env_file;
    fs::path txs_file;
    fs::path output_dir;
    fs::path output_result_file;
    fs::path output_alloc_file;
    std::optional<intx::uint256> block_reward;

    for (int i = 0; i < argc; ++i)
    {
        const std::string_view arg{argv[i]};

        if (arg == "-v")
        {
            std::cout << "evmone-t8n " PROJECT_VERSION "\n";
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
            block_reward = intx::from_string<intx::uint256>(argv[i]);
    }

    state::BlockInfo block;
    state::State state;

    try  // FIXME: Remove and use noexcept json::parse function
    {
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
        // FIXME: Calculate difficulty properly
        j_result["currentDifficulty"] = "0x20000";
        j_result["currentBaseFee"] = hex0x(block.base_fee);

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
                auto idx = 0;
                for (const auto& j_tx : j_txs)
                {
                    const auto tx = test::from_json<state::Transaction>(j_tx);
                    const auto res = state::transition(state, block, tx, rev, vm);
                    if (holds_alternative<std::error_code>(res))
                    {
                        const auto ec = std::get<std::error_code>(res);
                        json::json j_rejected_tx;
                        j_rejected_tx["hash"] = j_tx["hash"];
                        j_rejected_tx["index"] = idx;
                        j_rejected_tx["error"] = ec.message();
                        j_result["rejected"].push_back(j_rejected_tx);
                    }
                    else
                    {
                        const auto& receipt = get<state::TransactionReceipt>(res);
                        const auto& tx_logs = receipt.logs;

                        txs_logs.insert(txs_logs.end(), tx_logs.begin(), tx_logs.end());
                        auto& j_receipt = j_result["receipts"][j_result["receipts"].size()];
                        j_receipt["transactionHash"] = j_tx["hash"];
                        j_receipt["gasUsed"] = hex0x(static_cast<uint64_t>(receipt.gas_used));
                        j_receipt["cumulativeGasUsed"] = j_receipt["gasUsed"];

                        j_receipt["blockHash"] = NULL_HEXSTRING_32;
                        j_receipt["contractAddress"] = NULL_HEXSTRING_20;
                        j_receipt["logsBloom"] = NULL_HEXSTRING_256;
                        j_receipt["logs"] = json::json::array();  // FIXME: Add to_json<state:Log>
                        j_receipt["root"] = "";
                        j_receipt["status"] = "0x1";
                        j_receipt["transactionIndex"] = hex0x(idx);
                    }

                    idx++;
                }
            }

            if (block_reward.has_value())
                state.touch(block.coinbase).balance += *block_reward;

            j_result["logsHash"] = hex0x(logs_hash(txs_logs));
            j_result["stateRoot"] = hex0x(state::mpt_hash(state.get_accounts()));
        }

        j_result["logsBloom"] = NULL_HEXSTRING_256;
        j_result["receiptsRoot"] = NULL_HEXSTRING_32;
        j_result["txRoot"] = NULL_HEXSTRING_32;

        std::ofstream{output_dir / output_result_file} << j_result;

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

        std::ofstream{output_dir / output_alloc_file} << j_alloc;
    }
    catch (...)
    {
        std::cerr << "Unhandled exception" << std::endl;
    }

    return 0;
}
