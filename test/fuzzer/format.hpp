#pragma once

#include "fuzz_types.hpp"

namespace fzz
{
std::optional<Test> deserialize(std::span<const uint8_t> data);
size_t serialize(const Test& test, std::span<uint8_t> data);
}
