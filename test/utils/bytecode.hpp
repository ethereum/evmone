// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <test/utils/utils.hpp>

struct bytecode;

inline bytecode push(uint64_t n);

struct bytecode : bytes
{
    bytecode() noexcept = default;

    bytecode(bytes b) : bytes(std::move(b)) {}

    bytecode(evmc_opcode opcode) : bytes{uint8_t(opcode)} {}

    template <typename T,
        typename = typename std::enable_if_t<std::is_convertible_v<T, std::string_view>>>
    bytecode(T hex) : bytes{from_hex(hex)}
    {}

    bytecode(uint64_t n) : bytes{push(n)} {}
};

inline bytecode operator+(bytecode a, bytecode b)
{
    return static_cast<bytes&>(a) + static_cast<bytes&>(b);
}

inline bytecode& operator+=(bytecode& a, bytecode b)
{
    return a = a + b;
}

inline bool operator==(const bytecode& a, const bytecode& b) noexcept
{
    return static_cast<const bytes&>(a) == static_cast<const bytes&>(b);
}

inline std::ostream& operator<<(std::ostream& os, const bytecode& c)
{
    return os << to_hex(c);
}

inline bytecode operator*(int n, bytecode c)
{
    auto out = bytecode{};
    while (n-- > 0)
        out += c;
    return out;
}

inline bytecode operator*(int n, evmc_opcode op)
{
    return n * bytecode{op};
}


inline bytecode push(bytes_view data)
{
    if (data.empty())
        throw std::invalid_argument{"push data empty"};
    if (data.size() > (OP_PUSH32 - OP_PUSH1 + 1))
        throw std::invalid_argument{"push data too long"};
    return evmc_opcode(data.size() + OP_PUSH1 - 1) + bytes{data};
}

inline bytecode push(std::string_view hex_data)
{
    return push(from_hex(hex_data));
}


inline bytecode push(uint64_t n)
{
    auto data = bytes{};
    for (; n != 0; n >>= 8)
        data.push_back(uint8_t(n));
    std::reverse(data.begin(), data.end());
    if (data.empty())
        data.push_back(0);
    return push(data);
}

inline bytecode dup1(bytecode c)
{
    return c + OP_DUP1;
}

inline bytecode add(bytecode a, bytecode b)
{
    return b + a + OP_ADD;
}

inline bytecode mstore(bytecode index)
{
    return index + OP_MSTORE;
}

inline bytecode mstore(bytecode index, bytecode value)
{
    return value + index + OP_MSTORE;
}

inline bytecode mstore8(bytecode index)
{
    return index + OP_MSTORE8;
}

inline bytecode mstore8(bytecode index, bytecode value)
{
    return value + index + OP_MSTORE8;
}

inline bytecode jump(bytecode target)
{
    return target + OP_JUMP;
}

inline bytecode jumpi(bytecode target, bytecode condition)
{
    return condition + target + OP_JUMPI;
}

inline bytecode ret(bytecode index, bytecode size)
{
    return size + index + OP_RETURN;
}

inline bytecode ret_top()
{
    return mstore(0) + ret(0, 0x20);
}

inline bytecode ret(bytecode c)
{
    return c + ret_top();
}

inline bytecode not_(bytecode c)
{
    return c + OP_NOT;
}

inline bytecode sha3(bytecode index, bytecode size)
{
    return size + index + OP_SHA3;
}

inline bytecode calldataload(bytecode index)
{
    return index + OP_CALLDATALOAD;
}

inline bytecode sstore(bytecode index, bytecode value)
{
    return value + index + OP_SSTORE;
}

inline bytecode sload(bytecode index)
{
    return index + OP_SLOAD;
}


inline std::string decode(bytes_view bytecode, evmc_revision rev)
{
    auto s = std::string{"bytecode{}"};
    const auto names = evmc_get_instruction_names_table(rev);
    for (auto it = bytecode.begin(); it != bytecode.end(); ++it)
    {
        const auto opcode = *it;
        if (const auto name = names[opcode]; name)
        {
            s += std::string{" + OP_"} + name;

            if (opcode >= OP_PUSH1 && opcode <= OP_PUSH32)
            {
                auto push_data = std::string{};
                auto push_data_size = opcode - OP_PUSH1 + 1;
                while (push_data_size-- && ++it != bytecode.end())
                    push_data += to_hex({&*it, 1});
                if (!push_data.empty())
                    s += " + \"" + push_data + '"';
                if (it == bytecode.end())
                    break;
            }
        }
        else
            s += " + \"" + to_hex({&opcode, 1}) + '"';
    }

    return s;
}