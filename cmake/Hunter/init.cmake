# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2018-2019 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

set(HUNTER_CONFIGURATION_TYPES Release CACHE STRING "Build type of Hunter packages")

include(HunterGate)

HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.23.169.tar.gz"
    SHA1 "60de9f275143ab38df559986c04e3726683e7de7"
)
