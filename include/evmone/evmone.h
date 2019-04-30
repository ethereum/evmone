// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#ifndef EVMONE_H
#define EVMONE_H

#include <evmc/evmc.h>

extern "C" {
evmc_instance* evmc_create_evmone() noexcept;
}

#endif  // EVMONE_H
