// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "utils.hpp"

#if __GNUC__ >= 12
// Workaround the bug related to std::regex and std::function:
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105562.
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <regex>

bytes from_hexx(const std::string& hexx)
{
    const auto re = std::regex{R"(\((\d+)x([^)]+)\))"};

    auto hex = hexx;
    auto position_correction = size_t{0};
    for (auto it = std::sregex_iterator{hexx.begin(), hexx.end(), re}; it != std::sregex_iterator{};
         ++it)
    {
        auto num_repetitions = std::stoi((*it)[1]);
        auto replacement = std::string{};
        while (num_repetitions-- > 0)
            replacement += (*it)[2];

        const auto pos = static_cast<size_t>(it->position()) + position_correction;
        const auto length = static_cast<size_t>(it->length());
        hex.replace(pos, length, replacement);
        position_correction += replacement.length() - length;
    }
    return from_spaced_hex(hex).value();
}
