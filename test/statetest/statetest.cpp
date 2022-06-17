// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <iostream>

namespace
{
class StateTest : public testing::Test
{
    fs::path m_json_test_file;
    evmc::VM& m_vm;

public:
    explicit StateTest(fs::path json_test_file, evmc::VM& vm) noexcept
      : m_json_test_file{std::move(json_test_file)}, m_vm{vm}
    {}

    void TestBody() final
    {
        evmone::test::run_state_test(evmone::test::load_state_test(m_json_test_file), m_vm);
    }
};

void register_test(const std::string& suite_name, const fs::path& file, evmc::VM& vm)
{
    testing::RegisterTest(suite_name.c_str(), file.stem().string().c_str(), nullptr, nullptr,
        file.string().c_str(), 0,
        [file, &vm]() -> testing::Test* { return new StateTest(file, vm); });
}

void register_test_files(const fs::path& root, evmc::VM& vm)
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
            register_test(fs::relative(p, root).parent_path().string(), p, vm);
    }
    else if (is_regular_file(root))
    {
        register_test(root.parent_path().string(), root, vm);
    }
    else
        throw std::invalid_argument("invalid path: " + root.string());
}
}  // namespace


int main(int argc, char* argv[])
{
    try
    {
        evmc::VM vm{evmc_create_evmone(), {{"O", "0"}, /*{"trace", "1"}*/}};

        testing::InitGoogleTest(&argc, argv);  // Process GoogleTest flags.
        for (int i = 1; i < argc; ++i)
            register_test_files(argv[i], vm);
        return RUN_ALL_TESTS();
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
