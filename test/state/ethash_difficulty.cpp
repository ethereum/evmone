// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "ethash_difficulty.hpp"
#include <algorithm>
#include <cassert>

namespace evmone::state
{
namespace
{
int64_t get_bomb_delay(evmc_revision rev) noexcept
{
    switch (rev)
    {
    default:
        return 0;
    case EVMC_BYZANTIUM:
        return 3'000'000;
    case EVMC_CONSTANTINOPLE:
    case EVMC_PETERSBURG:
    case EVMC_ISTANBUL:
        return 5'000'000;
    case EVMC_BERLIN:
        return 9'000'000;
    case EVMC_LONDON:
        return 9'700'000;
    }
}
}  // namespace

int64_t calculate_difficulty(int64_t parent_difficulty, bool parent_has_ommers,
    int64_t parent_timestamp, int64_t current_timestamp, int64_t block_number,
    evmc_revision rev) noexcept
{
    // The calculation follows Ethereum Yellow Paper section 4.3.4. "Block Header Validity".

    if (rev >= EVMC_PARIS)
        return 0;  // No difficulty after the Merge.

    // TODO: Implement for older revisions
    if (rev < EVMC_BYZANTIUM)
        return 0x020000;

    static constexpr auto min_difficulty = int64_t{1} << 17;

    const auto delay = get_bomb_delay(rev);
    const auto fake_block_number = std::max(int64_t{0}, block_number - delay);
    const auto p = (fake_block_number / 100'000) - 2;
    assert(p < 63);
    const auto epsilon = p < 0 ? 0 : int64_t{1} << p;
    const auto y = parent_has_ommers ? 2 : 1;

    const auto timestamp_diff = current_timestamp - parent_timestamp;
    assert(timestamp_diff > 0);
    const auto sigma_2 = std::max(y - timestamp_diff / 9, int64_t{-99});
    const auto x = parent_difficulty / 2048;
    const auto difficulty = parent_difficulty + x * sigma_2 + epsilon;
    return std::max(min_difficulty, difficulty);
}
}  // namespace evmone::state
