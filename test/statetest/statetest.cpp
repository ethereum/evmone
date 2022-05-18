// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include <gtest/gtest.h>
#include <iostream>

namespace
{
class StateTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit StateTest(fs::path json_test_file) noexcept
      : m_json_test_file{std::move(json_test_file)}
    {}

    void TestBody() final { evmone::test::load_state_test(m_json_test_file); }
};
}  // namespace

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);  // Process GoogleTest flags.

    if (argc != 2)
    {
        std::cerr << "Missing argument with the path to the tests directory\n";
        return -1;
    }

    std::vector<fs::path> test_files;
    const fs::path root_test_dir{argv[1]};
    std::copy_if(fs::recursive_directory_iterator{root_test_dir},
        fs::recursive_directory_iterator{}, std::back_inserter(test_files),
        [](const fs::directory_entry& entry) {
            return entry.is_regular_file() && entry.path().extension() == ".json";
        });
    std::sort(test_files.begin(), test_files.end());
    for (const auto& p : test_files)
    {
        const auto d = fs::relative(p, root_test_dir);
        testing::RegisterTest(d.parent_path().string().c_str(), d.stem().string().c_str(), nullptr,
            nullptr, p.string().c_str(), 0, [p]() -> testing::Test* { return new StateTest(p); });
    }

    return RUN_ALL_TESTS();
}
