// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/evmc.hpp>
#include <evmone/evmone.h>
#include <gtest/gtest.h>

TEST(evmone, info)
{
    auto vm = evmc::VM{evmc_create_evmone()};
    EXPECT_STREQ(vm.name(), "evmone");
    EXPECT_STREQ(vm.version(), PROJECT_VERSION);
    EXPECT_TRUE(vm.is_abi_compatible());
}

TEST(evmone, capabilities)
{
    auto vm = evmc_create_evmone();
    EXPECT_EQ(vm->get_capabilities(vm), evmc_capabilities_flagset{EVMC_CAPABILITY_EVM1});
    vm->destroy(vm);
}

TEST(evmone, set_option_invalid)
{
    auto vm = evmc_create_evmone();
    ASSERT_NE(vm->set_option, nullptr);
    EXPECT_EQ(vm->set_option(vm, "", ""), EVMC_SET_OPTION_INVALID_NAME);
    EXPECT_EQ(vm->set_option(vm, "o", ""), EVMC_SET_OPTION_INVALID_NAME);
    EXPECT_EQ(vm->set_option(vm, "0", ""), EVMC_SET_OPTION_INVALID_NAME);
    vm->destroy(vm);
}

TEST(evmone, set_option_optimization_level)
{
    auto vm = evmc::VM{evmc_create_evmone()};
    EXPECT_EQ(vm.set_option("O", ""), EVMC_SET_OPTION_INVALID_VALUE);
    EXPECT_EQ(vm.set_option("O", "0"), EVMC_SET_OPTION_SUCCESS);
    EXPECT_EQ(vm.set_option("O", "1"), EVMC_SET_OPTION_INVALID_VALUE);
    EXPECT_EQ(vm.set_option("O", "2"), EVMC_SET_OPTION_SUCCESS);
    EXPECT_EQ(vm.set_option("O", "3"), EVMC_SET_OPTION_INVALID_VALUE);

    EXPECT_EQ(vm.set_option("O", "20"), EVMC_SET_OPTION_INVALID_VALUE);
    EXPECT_EQ(vm.set_option("O", "21"), EVMC_SET_OPTION_INVALID_VALUE);
    EXPECT_EQ(vm.set_option("O", "22"), EVMC_SET_OPTION_INVALID_VALUE);
}
