// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <test/utils/utils.hpp>

#include <iomanip>
#include <iostream>
#include <regex>

bytes from_hex(std::string_view hex)
{
    if (hex.length() % 2 == 1)
        throw std::length_error{"the length of the input is odd"};

    bytes bs;
    int b = 0;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        auto h = hex[i];
        int v;
        if (h >= '0' && h <= '9')
            v = h - '0';
        else if (h >= 'a' && h <= 'f')
            v = h - 'a' + 10;
        else if (h >= 'A' && h <= 'F')
            v = h - 'A' + 10;
        else
            throw std::out_of_range{"not a hex digit"};

        if (i % 2 == 0)
            b = v << 4;
        else
            bs.push_back(static_cast<uint8_t>(b | v));
    }
    return bs;
}

std::string to_hex(bytes_view bs)
{
    std::string str;
    str.reserve(bs.size() * 2);
    for (auto b : bs)
        str += hex(b);
    return str;
}

bytes from_hexx(const std::string& hexx)
{
    const auto re = std::regex{R"(\((\d+)x([^)]+)\))"};

    auto hex = hexx;
    auto position_correction = int{0};
    for (auto it = std::sregex_iterator{hexx.begin(), hexx.end(), re}; it != std::sregex_iterator{};
         ++it)
    {
        auto num_repetitions = std::stoi((*it)[1]);
        auto replacement = std::string{};
        while (num_repetitions-- > 0)
            replacement += (*it)[2];

        hex.replace(it->position() + position_correction, it->length(), replacement);
        position_correction += static_cast<int>(replacement.length() - it->length());
    }
    return from_hex(hex);
}
