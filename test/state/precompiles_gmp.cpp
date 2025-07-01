// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_gmp.hpp"
#include <gmp.h>
#include <cassert>

namespace evmone::state
{
void expmod_gmp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept
{
    mpz_t b, e, m, r;  // NOLINT(*-isolate-declaration)
    mpz_inits(b, e, m, r, nullptr);
    mpz_import(b, base.size(), 1, 1, 0, 0, base.data());
    mpz_import(e, exp.size(), 1, 1, 0, 0, exp.data());
    mpz_import(m, mod.size(), 1, 1, 0, 0, mod.data());
    assert(mpz_sgn(m) != 0);

    mpz_powm(r, b, e, m);

    size_t export_size = 0;
    mpz_export(output, &export_size, 1, 1, 0, 0, r);
    assert(export_size <= mod.size());
    mpz_clears(b, e, m, r, nullptr);

    std::copy_backward(output, output + export_size, output + mod.size());
    std::fill_n(output, mod.size() - export_size, 0);
}
}  // namespace evmone::state
