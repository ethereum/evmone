// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#ifndef EVMONE_H
#define EVMONE_H

#include <evmc/evmc.h>

#if __cplusplus
extern "C" {
#endif

evmc_instance* evmc_create_evmone() noexcept;

#if __cplusplus
}
#endif

#endif  // EVMONE_H
