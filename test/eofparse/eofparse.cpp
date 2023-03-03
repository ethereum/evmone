// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/evmc.hpp>
#include <evmone/eof.hpp>
#include <iostream>
#include <string>

namespace
{
inline constexpr bool isalnum(char ch) noexcept
{
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

template <typename BaseIterator>
struct skip_nonalnum_iterator : evmc::filter_iterator<BaseIterator, isalnum>
{
    using evmc::filter_iterator<BaseIterator, isalnum>::filter_iterator;
};

template <typename BaseIterator>
skip_nonalnum_iterator(BaseIterator, BaseIterator) -> skip_nonalnum_iterator<BaseIterator>;

template <typename InputIterator>
std::optional<evmc::bytes> from_hex_skip_nonalnum(InputIterator begin, InputIterator end) noexcept
{
    evmc::bytes bs;
    if (!from_hex(skip_nonalnum_iterator{begin, end}, skip_nonalnum_iterator{end, end},
            std::back_inserter(bs)))
        return {};
    return bs;
}

}  // namespace

int main()
{
    try
    {
        for (std::string line; std::getline(std::cin, line);)
        {
            if (line.empty() || line.starts_with('#'))
                continue;

            auto o = from_hex_skip_nonalnum(line.begin(), line.end());
            if (!o)
            {
                std::cout << "err: invalid hex\n";
                continue;
            }

            const auto& eof = *o;
            const auto err = evmone::validate_eof(EVMC_CANCUN, eof);
            if (err != evmone::EOFValidationError::success)
            {
                std::cout << "err: " << evmone::get_error_message(err) << "\n";
                continue;
            }

            const auto header = evmone::read_valid_eof1_header(eof);
            std::cout << "OK ";
            for (size_t i = 0; i < header.code_sizes.size(); ++i)
            {
                if (i != 0)
                    std::cout << ",";
                std::cout << evmc::hex(header.get_code(eof, i));
            }
            std::cout << "\n";
        }
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}
