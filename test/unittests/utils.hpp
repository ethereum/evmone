// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>

#include <gtest/gtest.h>
#include <iostream>

using bytes = std::basic_string<uint8_t>;

inline bytes from_hex(const char hex[]) noexcept
{
    bytes bs;
    int b = 0;
    for (size_t i = 0; hex[i] != 0; ++i)
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

inline std::string to_hex(const uint8_t bytes[], size_t size)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        str.push_back(hex_chars[bytes[i] >> 4]);
        str.push_back(hex_chars[bytes[i] & 0xf]);
    }
    return str;
}


const auto fake_fn_table = []() noexcept
{
    evmone::exec_fn_table fns;
    for (size_t i = 0; i < fns.size(); ++i)
        fns[i] = (evmone::exec_fn)i;
    return fns;
}
();

void dump_analysis(const evmone::code_analysis& analysis);
