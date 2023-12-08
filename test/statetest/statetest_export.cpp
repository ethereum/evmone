// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"

namespace evmone::test
{
json::json to_json(const std::unordered_map<address, state::Account>& accounts)
{
    json::json j;
    for (const auto& [addr, acc] : accounts)
    {
        auto& j_acc = j[hex0x(addr)];
        j_acc["nonce"] = hex0x(acc.nonce);
        j_acc["balance"] = hex0x(acc.balance);
        j_acc["code"] = hex0x(bytes_view(acc.code.data(), acc.code.size()));

        auto& j_storage = j_acc["storage"] = json::json::object();
        for (const auto& [key, val] : acc.storage)
        {
            if (!is_zero(val.current))
                j_storage[hex0x(key)] = hex0x(val.current);
        }
    }
    return j;
}
}  // namespace evmone::test
