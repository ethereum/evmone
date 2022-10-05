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

void register_test(const std::string& suite_name, const fs::path& file)
{
    testing::RegisterTest(suite_name.c_str(), file.stem().string().c_str(), nullptr, nullptr,
        file.string().c_str(), 0, [file]() -> testing::Test* { return new StateTest(file); });
}

void register_test_files(const fs::path& root)
{
    if (is_directory(root))
    {
        std::vector<fs::path> test_files;
        std::copy_if(fs::recursive_directory_iterator{root}, fs::recursive_directory_iterator{},
            std::back_inserter(test_files), [](const fs::directory_entry& entry) {
                return entry.is_regular_file() && entry.path().extension() == ".json";
            });
        std::sort(test_files.begin(), test_files.end());

        for (const auto& p : test_files)
            register_test(fs::relative(p, root).parent_path().string(), p);
    }
    else  // Assume regular file.
    {
        register_test(root.parent_path().string(), root);
    }
}
}  // namespace


int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);  // Process GoogleTest flags.
    for (int i = 1; i < argc; ++i)
        register_test_files(argv[i]);
    return RUN_ALL_TESTS();
}
