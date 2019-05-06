// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <test/utils/utils.hpp>

#include <iomanip>
#include <iostream>

bytes from_hex(std::string_view hex)
{
    bytes bs;
    int b = 0;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        auto h = hex[i];
        int v = (h <= '9') ? h - '0' : h - 'a' + 10;

        if (i % 2 == 0)
            b = v << 4;
        else
            bs.push_back(static_cast<uint8_t>(b | v));
    }
    return bs;
}

std::string to_hex(bytes_view bytes)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(bytes.size() * 2);
    for (auto b : bytes)
    {
        str.push_back(hex_chars[b >> 4]);
        str.push_back(hex_chars[b & 0xf]);
    }
    return str;
}
