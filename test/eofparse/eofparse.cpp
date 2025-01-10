// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <CLI/CLI.hpp>
#include <evmc/evmc.hpp>
#include <evmone/eof.hpp>
#include <iostream>
#include <string>

namespace
{
constexpr bool isalnum(char ch) noexcept
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

int main(int argc, char* argv[])
{
    try
    {
        CLI::App app{"evmone eofparse tool"};
        const auto& initcode_flag =
            *app.add_flag("--initcode", "Validate code as initcode containers");

        app.parse(argc, argv);
        const auto container_kind =
            initcode_flag ? evmone::ContainerKind::initcode : evmone::ContainerKind::runtime;

        int num_errors = 0;
        for (std::string line; std::getline(std::cin, line);)
        {
            if (line.empty() || line.starts_with('#'))
                continue;

            auto o = from_hex_skip_nonalnum(line.begin(), line.end());
            if (!o)
            {
                std::cout << "err: invalid hex\n";
                ++num_errors;
                continue;
            }

            const auto& eof = *o;
            const auto err = evmone::validate_eof(EVMC_OSAKA, container_kind, eof);
            if (err != evmone::EOFValidationError::success)
            {
                std::cout << "err: " << evmone::get_error_message(err) << "\n";
                ++num_errors;
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
        return num_errors;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
