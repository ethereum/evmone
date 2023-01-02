// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/evmc.hpp>
#include <evmone/eof.hpp>
#include <iostream>
#include <string>

int main()
{
    try
    {
        for (std::string line; std::getline(std::cin, line);)
        {
            const auto eof = evmc::from_hex(line).value();

            const auto err = evmone::validate_eof(EVMC_SHANGHAI, eof);
            if (err != evmone::EOFValidationError::success)
            {
                std::cout << "err: " << evmone::get_error_message(err);
            }
            else
            {
                const auto header = evmone::read_valid_eof1_header(eof);

                std::cout << "OK ";
                for (size_t i = 0; i < header.code_sizes.size(); ++i)
                {
                    if (i != 0)
                        std::cout << ',';
                    std::cout << evmc::hex(
                        evmc::bytes_view{&eof[header.code_offsets.at(i)], header.code_sizes[i]});
                }
            }
            std::cout << std::endl;
        }
    }
    catch (const std::bad_optional_access&)
    {
        std::cerr << "invalid hex\n";
        return 1;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << '\n';
        return 2;
    }

    return 0;
}
