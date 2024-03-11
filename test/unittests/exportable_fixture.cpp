// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#ifdef _MSC_VER
// Disable warning C4996: 'getenv': This function or variable may be unsafe.
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "exportable_fixture.hpp"
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

namespace evmone::test
{
namespace
{
/// Creates the file path for the exported test based on its name.
fs::path get_export_test_path(const testing::TestInfo& test_info, std::string_view export_dir)
{
    const std::string suite_name{test_info.test_suite_name()};

    const auto stem = fs::path{test_info.file()}.stem().string();
    const std::regex re{suite_name + "_(.*)_test"};
    std::smatch m;
    const auto sub_suite_name = std::regex_match(stem, m, re) ? m[1] : std::string{};

    const auto dir = fs::path{export_dir} / suite_name / sub_suite_name;

    fs::create_directories(dir);
    return dir / (std::string{test_info.name()} + ".json");
}
}  // namespace

ExportableFixture::ExportableFixture()
{
    if (const auto export_dir = std::getenv("EVMONE_EXPORT_TESTS"); export_dir != nullptr)
    {
        const auto& test_info = *testing::UnitTest::GetInstance()->current_test_info();
        export_test_name = test_info.name();
        export_file_path = get_export_test_path(test_info, export_dir).string();
    }
}
}  // namespace evmone::test
