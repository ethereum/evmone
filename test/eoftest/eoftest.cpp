// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0


#include "eoftest.hpp"
#include <CLI/CLI.hpp>
#include <gtest/gtest.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace
{

class EOFTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit EOFTest(fs::path json_test_file) noexcept : m_json_test_file{std::move(json_test_file)}
    {}

    void TestBody() final
    {
        std::ifstream f{m_json_test_file};
        evmone::test::run_eof_test(f);
    }
};

void register_test(const std::string& suite_name, const fs::path& file)
{
    testing::RegisterTest(suite_name.c_str(), file.stem().string().c_str(), nullptr, nullptr,
        file.string().c_str(), 0, [file]() -> testing::Test* { return new EOFTest(file); });
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
        std::ranges::sort(test_files);

        for (const auto& p : test_files)
            register_test(fs::relative(p, root).parent_path().string(), p);
    }
    else  // Treat as a file.
    {
        register_test(root.parent_path().string(), root);
    }
}

}  // namespace


int main(int argc, char* argv[])
{
    try
    {
        testing::InitGoogleTest(&argc, argv);
        CLI::App app{"evmone eof test runner"};

        std::vector<std::string> paths;
        app.add_option("path", paths, "Path to test file or directory")
            ->required()
            ->check(CLI::ExistingPath);

        CLI11_PARSE(app, argc, argv);

        for (const auto& p : paths)
        {
            register_test_files(p);
        }

        return RUN_ALL_TESTS();
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
