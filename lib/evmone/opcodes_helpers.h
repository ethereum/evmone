// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#define ANY_SMALL_PUSH \
    OP_PUSH1:          \
    case OP_PUSH2:     \
    case OP_PUSH3:     \
    case OP_PUSH4:     \
    case OP_PUSH5:     \
    case OP_PUSH6:     \
    case OP_PUSH7:     \
    case OP_PUSH8

#define ANY_LARGE_PUSH \
    OP_PUSH9:          \
    case OP_PUSH10:    \
    case OP_PUSH11:    \
    case OP_PUSH12:    \
    case OP_PUSH13:    \
    case OP_PUSH14:    \
    case OP_PUSH15:    \
    case OP_PUSH16:    \
    case OP_PUSH17:    \
    case OP_PUSH18:    \
    case OP_PUSH19:    \
    case OP_PUSH20:    \
    case OP_PUSH21:    \
    case OP_PUSH22:    \
    case OP_PUSH23:    \
    case OP_PUSH24:    \
    case OP_PUSH25:    \
    case OP_PUSH26:    \
    case OP_PUSH27:    \
    case OP_PUSH28:    \
    case OP_PUSH29:    \
    case OP_PUSH30:    \
    case OP_PUSH31:    \
    case OP_PUSH32

#define ANY_DUP    \
    OP_DUP1:       \
    case OP_DUP2:  \
    case OP_DUP3:  \
    case OP_DUP4:  \
    case OP_DUP5:  \
    case OP_DUP6:  \
    case OP_DUP7:  \
    case OP_DUP8:  \
    case OP_DUP9:  \
    case OP_DUP10: \
    case OP_DUP11: \
    case OP_DUP12: \
    case OP_DUP13: \
    case OP_DUP14: \
    case OP_DUP15: \
    case OP_DUP16

#define ANY_SWAP    \
    OP_SWAP1:       \
    case OP_SWAP2:  \
    case OP_SWAP3:  \
    case OP_SWAP4:  \
    case OP_SWAP5:  \
    case OP_SWAP6:  \
    case OP_SWAP7:  \
    case OP_SWAP8:  \
    case OP_SWAP9:  \
    case OP_SWAP10: \
    case OP_SWAP11: \
    case OP_SWAP12: \
    case OP_SWAP13: \
    case OP_SWAP14: \
    case OP_SWAP15: \
    case OP_SWAP16
