

// void op_stop(execution_state& state, instr_argument) noexcept
// {
//     state.run = false;
// }

// void op_add(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] += state.stack[state.stack_ptr];
//     state.stack_ptr--;
// }

// void op_mul(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] *= state.stack[state.stack_ptr];
//     state.stack_ptr--;
// }

// void op_sub(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] - state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_div(execution_state& state, instr_argument) noexcept
// {
//     auto& v = state.stack[state.stack_ptr - 1];
//     v = v != 0 ? state.stack[state.stack_ptr] / v : 0;
//     state.stack_ptr--;
// }

// void op_sdiv(execution_state& state, instr_argument) noexcept
// {
//     auto& v = state.stack[state.stack_ptr - 1];
//     v = v != 0 ? intx::sdivrem(state.stack[state.stack_ptr], v).quot : 0;
//     state.stack_ptr--;
// }

// void op_mod(execution_state& state, instr_argument) noexcept
// {
//     auto& v = state.stack[state.stack_ptr - 1];
//     v = v != 0 ? state.stack[state.stack_ptr] % v : 0;
//     state.stack_ptr--;
// }

// void op_smod(execution_state& state, instr_argument) noexcept
// {
//     auto& v = state.stack[state.stack_ptr - 1];
//     v = v != 0 ? intx::sdivrem(state.stack[state.stack_ptr], v).rem : 0;
//     state.stack_ptr--;
// }

// void op_addmod(execution_state& state, instr_argument) noexcept
// {
//     using intx::uint512;
//     auto x = state.stack[state.stack_ptr];
//     auto y = state.stack[state.stack_ptr - 1];
//     auto m = state.stack[state.stack_ptr - 2];
    
//     state.stack_ptr -= 2;
//     state.stack[state.stack_ptr] = m != 0 ? ((uint512{x} + uint512{y}) % uint512{m}).lo : 0;
// }

// void op_mulmod(execution_state& state, instr_argument) noexcept
// {
//     using intx::uint512;
//     auto x = state.stack[state.stack_ptr];
//     auto y = state.stack[state.stack_ptr - 1];
//     auto m = state.stack[state.stack_ptr - 2];
    
//     state.stack_ptr -= 2;
//     state.stack[state.stack_ptr] = m != 0 ? ((uint512{x} * uint512{y}) % uint512{m}).lo : 0;
// }

// void op_exp(execution_state& state, instr_argument arg) noexcept
// {
//     auto base = state.stack[state.stack_ptr];
//     auto& exponent = state.stack[state.stack_ptr - 1];

//     auto exponent_significant_bytes = intx::count_significant_words<uint8_t>(exponent);

//     auto additional_cost = exponent_significant_bytes * arg.number;
//     state.gas_left -= additional_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     exponent = intx::exp(base, exponent);
//     state.stack_ptr--;
// }

// void op_signextend(execution_state& state, instr_argument) noexcept
// {
//     auto ext = state.stack[state.stack_ptr];
//     auto& x = state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;

//     if (ext < 31)
//     {
//         auto sign_bit = static_cast<int>(ext) * 8 + 7;
//         auto sign_mask = intx::uint256{1} << sign_bit;
//         // TODO: Fix intx operator- overloading: X - 1 does not work.
//         auto value_mask = sign_mask - intx::uint256{1};
//         auto is_neg = (x & sign_mask) != 0;
//         x = is_neg ? x | ~value_mask : x & value_mask;
//     }
// }

// void op_lt(execution_state& state, instr_argument) noexcept
// {
//     // OPT: Have single function implementing all comparisons.
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] < state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_gt(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr - 1] < state.stack[state.stack_ptr];
//     state.stack_ptr--;
// }

// void op_slt(execution_state& state, instr_argument) noexcept
// {
//     auto x = state.stack[state.stack_ptr];
//     auto y = state.stack[state.stack_ptr - 1];
//     auto x_neg = static_cast<bool>(x >> 255);
//     auto y_neg = static_cast<bool>(y >> 255);
//     state.stack[state.stack_ptr - 1] = (x_neg ^ y_neg) ? x_neg : x < y;
//     state.stack_ptr--;
// }

// void op_sgt(execution_state& state, instr_argument) noexcept
// {
//     auto x = state.stack[state.stack_ptr];
//     auto y = state.stack[state.stack_ptr - 1];
//     auto x_neg = static_cast<bool>(x >> 255);
//     auto y_neg = static_cast<bool>(y >> 255);
//     state.stack[state.stack_ptr - 1] = (x_neg ^ y_neg) ? y_neg : y < x;
//     state.stack_ptr--;
// }

// void op_eq(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] == state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_iszero(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr] = state.stack[state.stack_ptr] == 0;
// }

// void op_and(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Add operator&= to intx.
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] & state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_or(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] | state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_xor(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr] ^ state.stack[state.stack_ptr - 1];
//     state.stack_ptr--;
// }

// void op_not(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr] = ~state.stack[state.stack_ptr];
// }

// void op_byte(execution_state& state, instr_argument) noexcept
// {
//     auto n = state.stack[state.stack_ptr];
//     auto& x = state.stack[state.stack_ptr - 1];

//     if (31 < n)
//         x = 0;
//     else
//     {
//         auto sh = (31 - static_cast<unsigned>(n)) * 8;
//         auto y = x >> sh;
//         x = y & intx::uint256(0xff);  // TODO: Fix intx operator&.
//     }

//     state.stack_ptr--;
// }

// void op_shl(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Use =<<.
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr - 1] << state.stack[state.stack_ptr];
//     state.stack_ptr--;
// }

// void op_shr(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Use =>>.
//     state.stack[state.stack_ptr - 1] = state.stack[state.stack_ptr - 1] >> state.stack[state.stack_ptr];
//     state.stack_ptr--;
// }

// void op_sar(execution_state& state, instr_argument arg) noexcept
// {
//     // TODO: Fix explicit conversion to bool in intx.
//     if ((state.stack[state.stack_ptr - 1] & (intx::uint256{1} << 255)) == 0)
//         return op_shr(state, arg);

//     constexpr auto allones = ~uint256{};

//     if (state.stack[state.stack_ptr] >= 256)
//         state.stack[state.stack_ptr - 1] = allones;
//     else
//     {
//         const auto shift = static_cast<unsigned>(state.stack[state.stack_ptr]);
//         state.stack[state.stack_ptr - 1] = (state.stack[state.stack_ptr - 1] >> shift) | (allones << (256 - shift));
//     }

//     state.stack_ptr--;
// }

// void op_sha3(execution_state& state, instr_argument) noexcept
// {
//     auto index = state.stack[state.stack_ptr];
//     auto size = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, index, size))
//         return;

//     auto i = static_cast<size_t>(index);
//     auto s = static_cast<size_t>(size);
//     auto w = (static_cast<int64_t>(s) + 31) / 32;
//     auto cost = w * 6;
//     state.gas_left -= cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     auto h = ethash::keccak256(&state.memory[i], s);

//     state.stack_ptr--;
//     state.stack[state.stack_ptr] = intx::be::uint256(h.bytes);
// }

// void op_address(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Might be generalized using pointers to class member.
//     uint8_t data[32] = {};
//     std::memcpy(&data[12], state.msg->destination.bytes, sizeof(state.msg->destination));
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(data);
// }

// void op_balance(execution_state& state, instr_argument) noexcept
// {
//     auto& x = state.stack[state.stack_ptr];
//     uint8_t data[32];
//     intx::be::store(data, x);
//     evmc_address addr;
//     std::memcpy(addr.bytes, &data[12], sizeof(addr));
//     x = intx::be::uint256(state.host->host->get_balance(state.host, &addr).bytes);
// }

// void op_origin(execution_state& state, instr_argument) noexcept
// {
//     if (__builtin_expect(state.tx_context.block_timestamp == 0, 0))
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     uint8_t data[32] = {};
//     std::memcpy(&data[12], state.tx_context.tx_origin.bytes, sizeof(state.tx_context.tx_origin));
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(data);
// }

// void op_caller(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Might be generalized using pointers to class member.
//     uint8_t data[32] = {};
//     std::memcpy(&data[12], state.msg->sender.bytes, sizeof(state.msg->sender));
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(data);
// }

// void op_callvalue(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(state.msg->value.bytes);// .push_back(a);
// }

// void op_calldataload(execution_state& state, instr_argument) noexcept
// {
//     auto& index = state.stack[state.stack_ptr];

//     if (state.msg->input_size < index)
//         index = 0;
//     else
//     {
//         const auto begin = static_cast<size_t>(index);
//         const auto end = std::min(begin + 32, state.msg->input_size);

//         uint8_t data[32] = {};
//         for (size_t i = 0; i < (end - begin); ++i)
//             data[i] = state.msg->input_data[begin + i];

//         index = intx::be::uint256(data);
//     }
// }

// void op_calldatasize(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::uint256{state.msg->input_size};
// }

// void op_calldatacopy(execution_state& state, instr_argument) noexcept
// {
//     auto mem_index = state.stack[state.stack_ptr];
//     auto input_index = state.stack[state.stack_ptr - 1];
//     auto size = state.stack[state.stack_ptr - 2];

//     if (!check_memory(state, mem_index, size))
//         return;

//     auto dst = static_cast<size_t>(mem_index);
//     auto src = state.msg->input_size < input_index ? state.msg->input_size :
//                                                      static_cast<size_t>(input_index);
//     auto s = static_cast<size_t>(size);
//     auto copy_size = std::min(s, state.msg->input_size - src);

//     auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
//     state.gas_left -= copy_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);
//     std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

//     state.stack_ptr -= 3;
// }

// void op_codesize(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::uint256{state.code_size};
// }

// void op_codecopy(execution_state& state, instr_argument) noexcept
// {
//     auto mem_index = state.stack[state.stack_ptr];
//     auto input_index = state.stack[state.stack_ptr - 1];
//     auto size = state.stack[state.stack_ptr - 2];

//     if (!check_memory(state, mem_index, size))
//         return;

//     auto dst = static_cast<size_t>(mem_index);
//     auto src = state.code_size < input_index ? state.code_size : static_cast<size_t>(input_index);
//     auto s = static_cast<size_t>(size);
//     auto copy_size = std::min(s, state.code_size - src);

//     auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
//     state.gas_left -= copy_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     std::memcpy(&state.memory[dst], &state.code[src], copy_size);
//     std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

//     state.stack_ptr -= 3;
// }

// void op_mload(execution_state& state, instr_argument) noexcept
// {
//     auto& index = state.stack[state.stack_ptr];

//     if (!check_memory(state, index, 32))
//         return;

//     index = intx::be::uint256(&state.memory[static_cast<size_t>(index)]);
// }

// void op_mstore(execution_state& state, instr_argument) noexcept
// {
//     auto index = state.stack[state.stack_ptr];
//     auto x = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, index, 32))
//         return;

//     intx::be::store(&state.memory[static_cast<size_t>(index)], x);

//     state.stack_ptr -= 2;
// }

// void op_mstore8(execution_state& state, instr_argument) noexcept
// {
//     auto index = state.stack[state.stack_ptr];
//     auto x = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, index, 1))
//         return;

//     state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(x);

//     state.stack_ptr -= 2;
// }

// void op_sload(execution_state& state, instr_argument) noexcept
// {
//     auto& x = state.stack[state.stack_ptr];
//     evmc_bytes32 key;
//     intx::be::store(key.bytes, x);
//     x = intx::be::uint256(
//         state.host->host->get_storage(state.host, &state.msg->destination, &key).bytes);
// }

// void op_sstore(execution_state& state, instr_argument arg) noexcept
// {
//     if (state.msg->flags & EVMC_STATIC)
//     {
//         // TODO: Implement static mode violation in analysis.
//         state.run = false;
//         state.status = EVMC_STATIC_MODE_VIOLATION;
//         return;
//     }

//     evmc_bytes32 key;
//     evmc_bytes32 value;
//     intx::be::store(key.bytes, state.stack[state.stack_ptr]);
//     intx::be::store(value.bytes, state.stack[state.stack_ptr - 1]);
//     state.stack_ptr -= 2;
//     auto status = state.host->host->set_storage(state.host, &state.msg->destination, &key, &value);
//     auto rev = static_cast<evmc_revision>(arg.number);
//     int cost = 0;
//     switch (status)
//     {
//     case EVMC_STORAGE_UNCHANGED:
//         cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
//         break;
//     case EVMC_STORAGE_MODIFIED:
//         cost = 5000;
//         break;
//     case EVMC_STORAGE_MODIFIED_AGAIN:
//         cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
//         break;
//     case EVMC_STORAGE_ADDED:
//         cost = 20000;
//         break;
//     case EVMC_STORAGE_DELETED:
//         cost = 5000;
//         break;
//     }
//     state.gas_left -= cost;
//     if (state.gas_left < 0)
//     {
//         state.status = EVMC_OUT_OF_GAS;
//         state.run = false;
//     }
// }

// void op_jump(execution_state& state, instr_argument) noexcept
// {
//     auto dst = state.stack[state.stack_ptr];
//     // TODO: validate this is a valid instruction...
//     state.pc = static_cast<size_t>(dst);
//     // int pc = -1;
//     // if (std::numeric_limits<int>::max() < dst ||
//     //     (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
//     // {
//     //     state.run = false;
//     //     state.status = EVMC_BAD_JUMP_DESTINATION;
//     //     return;
//     // }

//     // state.pc = static_cast<size_t>(pc);
//     state.stack_ptr--;
// }

// void op_jumpi(execution_state& state, instr_argument) noexcept
// {
//     auto condition = state.stack[state.stack_ptr - 1];
//     if (condition != 0)
//     {
//         // TODO: Call op_jump here.
//         auto dst = state.stack[state.stack_ptr];
//         // TODO: validate this is a valid instruction
//         state.pc = static_cast<size_t>(dst);
//         // int pc = -1;
//         // if (std::numeric_limits<int>::max() < dst ||
//         //     (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
//         // {
//         //     state.run = false;
//         //     state.status = EVMC_BAD_JUMP_DESTINATION;
//         //     return;
//         // }
//         // state.pc = static_cast<size_t>(pc);
//     }

//     state.stack_ptr -= 2;
// }

// void op_pc(execution_state& state, instr_argument arg) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = arg.number;
// }

// void op_msize(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = state.memory.size();
// }

// void op_gas(execution_state& state, instr_argument arg) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = static_cast<uint64_t>(state.gas_left + state.current_block_cost - arg.number);
// }

// void op_jumpdest(execution_state&, instr_argument) noexcept
// {
//     // OPT: We can skip JUMPDEST instruction in analysis.
// }

// void op_gasprice(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     state.stack[state.stack_ptr ] = intx::be::uint256(state.tx_context.tx_gas_price.bytes);
// }

// void op_extcodesize(execution_state& state, instr_argument) noexcept
// {
//     auto& x = state.stack[state.stack_ptr];
//     uint8_t data[32];
//     intx::be::store(data, x);
//     evmc_address addr;
//     std::memcpy(addr.bytes, &data[12], sizeof(addr));
//     x = state.host->host->get_code_size(state.host, &addr);
// }

// void op_extcodecopy(execution_state& state, instr_argument) noexcept
// {
//     auto addr_data = state.stack[state.stack_ptr];
//     auto mem_index = state.stack[state.stack_ptr - 1];
//     auto input_index = state.stack[state.stack_ptr - 2];
//     auto size = state.stack[state.stack_ptr - 3];

//     if (!check_memory(state, mem_index, size))
//         return;

//     auto dst = static_cast<size_t>(mem_index);
//     // FIXME: Bug, it should not use state.code_size;
//     auto src = state.code_size < input_index ? state.code_size : static_cast<size_t>(input_index);
//     auto s = static_cast<size_t>(size);

//     auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
//     state.gas_left -= copy_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     uint8_t data[32];
//     intx::be::store(data, addr_data);
//     evmc_address addr;
//     std::memcpy(addr.bytes, &data[12], sizeof(addr));

//     auto num_bytes_copied =
//         state.host->host->copy_code(state.host, &addr, src, &state.memory[dst], s);

//     std::memset(&state.memory[dst + num_bytes_copied], 0, s - num_bytes_copied);

//     state.stack_ptr -= 4;
// }

// void op_returndatasize(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = state.return_data.size();
// }

// void op_returndatacopy(execution_state& state, instr_argument) noexcept
// {
//     auto mem_index = state.stack[state.stack_ptr];
//     auto input_index = state.stack[state.stack_ptr - 1];
//     auto size = state.stack[state.stack_ptr - 2];

//     state.stack_ptr -= 3;

//     if (!check_memory(state, mem_index, size))
//         return;

//     auto dst = static_cast<size_t>(mem_index);
//     auto s = static_cast<size_t>(size);

//     if (state.return_data.size() < input_index)
//     {
//         state.run = false;
//         state.status = EVMC_INVALID_MEMORY_ACCESS;
//         return;
//     }
//     auto src = static_cast<size_t>(input_index);

//     if (src + s > state.return_data.size())
//     {
//         state.run = false;
//         state.status = EVMC_INVALID_MEMORY_ACCESS;
//         return;
//     }

//     auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
//     state.gas_left -= copy_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     std::memcpy(&state.memory[dst], &state.return_data[src], s);
// }

// void op_extcodehash(execution_state& state, instr_argument) noexcept
// {
//     auto& x = state.stack[state.stack_ptr];
//     uint8_t data[32];
//     intx::be::store(data, x);
//     evmc_address addr;
//     std::memcpy(addr.bytes, &data[12], sizeof(addr));
//     x = intx::be::uint256(state.host->host->get_code_hash(state.host, &addr).bytes);
// }

// void op_blockhash(execution_state& state, instr_argument) noexcept
// {
//     auto& number = state.stack[state.stack_ptr];

//     // Load transaction context.
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);

//     auto upper_bound = state.tx_context.block_number;
//     auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
//     auto n = static_cast<int64_t>(number);
//     auto header = evmc_bytes32{};
//     if (number < upper_bound && n >= lower_bound)
//         header = state.host->host->get_block_hash(state.host, n);
//     number = intx::be::uint256(header.bytes);
// }

// void op_coinbase(execution_state& state, instr_argument) noexcept
// {
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     uint8_t data[32] = {};
//     std::memcpy(
//         &data[12], state.tx_context.block_coinbase.bytes, sizeof(state.tx_context.block_coinbase));
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(data);
// }

// void op_timestamp(execution_state& state, instr_argument) noexcept
// {
//     // TODO: Extract lazy tx context fetch.
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::uint256{static_cast<uint64_t>(state.tx_context.block_timestamp)};
// }

// void op_number(execution_state& state, instr_argument) noexcept
// {
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::uint256{static_cast<uint64_t>(state.tx_context.block_number)};
// }

// void op_difficulty(execution_state& state, instr_argument) noexcept
// {
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(state.tx_context.block_difficulty.bytes);
// }

// void op_gaslimit(execution_state& state, instr_argument) noexcept
// {
//     if (state.tx_context.block_timestamp == 0)
//         state.tx_context = state.host->host->get_tx_context(state.host);
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::uint256{static_cast<uint64_t>(state.tx_context.block_gas_limit)};
// }

// void op_push1(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 1;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push2(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 2;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push3(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 3;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push4(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 4;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push5(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 5;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push6(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 6;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push7(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 7;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push8(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 8;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push9(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 9;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push10(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 10;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push11(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 11;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push12(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 12;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push13(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 13;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push14(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 14;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push15(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 15;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push16(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 16;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push17(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 17;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push18(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 18;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push19(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 19;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push20(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 20;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push21(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 21;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push22(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 22;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push23(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 23;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push24(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 24;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push25(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 25;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push26(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 26;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push27(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 27;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push28(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 28;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push29(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 29;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push30(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 30;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push31(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 31;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// void op_push32(execution_state& state, instr_argument arg) noexcept
// {
//     state.pc += 32;
//     // OPT: For smaller pushes, use pointer data directly.
//     state.stack_ptr++;
//     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// }

// // void op_pushfull(execution_state& state, instr_argument arg) noexcept
// // {
// //     // OPT: For smaller pushes, use pointer data directly.
// //     state.stack_ptr++;
// //     state.stack[state.stack_ptr] = intx::be::uint256(arg.data);
// // }

// void op_pop(execution_state& state, instr_argument) noexcept
// {
//     state.stack_ptr--;
// }

// void op_dup1(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr];
//     state.stack_ptr++;
// }

// void op_dup2(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 1];
//     state.stack_ptr++;
// }

// void op_dup3(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 2];
//     state.stack_ptr++;
// }

// void op_dup4(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 3];
//     state.stack_ptr++;
// }

// void op_dup5(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 4];
//     state.stack_ptr++;
// }

// void op_dup6(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 5];
//     state.stack_ptr++;
// }

// void op_dup7(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 6];
//     state.stack_ptr++;
// }

// void op_dup8(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 7];
//     state.stack_ptr++;
// }

// void op_dup9(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 8];
//     state.stack_ptr++;
// }

// void op_dup10(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 9];
//     state.stack_ptr++;
// }

// void op_dup11(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 10];
//     state.stack_ptr++;
// }

// void op_dup12(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 11];
//     state.stack_ptr++;
// }

// void op_dup13(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 12];
//     state.stack_ptr++;
// }

// void op_dup14(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 13];
//     state.stack_ptr++;
// }

// void op_dup15(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 14];
//     state.stack_ptr++;
// }

// void op_dup16(execution_state& state, instr_argument) noexcept
// {
//     state.stack[state.stack_ptr + 1] = state.stack[state.stack_ptr - 15];
//     state.stack_ptr++;
// }
// void op_swap1(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 1]);
// }

// void op_swap2(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 2]);
// }

// void op_swap3(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 3]);
// }

// void op_swap4(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 4]);
// }

// void op_swap5(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 5]);
// }

// void op_swap6(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 6]);
// }

// void op_swap7(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 7]);
// }

// void op_swap8(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 8]);
// }

// void op_swap9(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 9]);
// }

// void op_swap10(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 10]);
// }

// void op_swap11(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 11]);
// }

// void op_swap12(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 12]);
// }

// void op_swap13(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 13]);
// }

// void op_swap14(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 14]);
// }

// void op_swap15(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 15]);
// }

// void op_swap16(execution_state& state, instr_argument) noexcept
// {
//     std::swap(state.stack[state.stack_ptr], state.stack[state.stack_ptr - 16]);
// }


// void op_log(execution_state& state, int number) noexcept
// {
//     if (state.msg->flags & EVMC_STATIC)
//     {
//         // TODO: Implement static mode violation in analysis.
//         state.run = false;
//         state.status = EVMC_STATIC_MODE_VIOLATION;
//         return;
//     }

//     auto offset = state.stack[state.stack_ptr];
//     auto size = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, offset, size))
//         return;

//     auto o = static_cast<size_t>(offset);
//     auto s = static_cast<size_t>(size);

//     auto cost = int64_t{8} * s;
//     state.gas_left -= cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//     }

//     state.stack_ptr -= 2;

//     std::array<evmc_bytes32, 4> topics;
//     for (auto i = 0; i < number; ++i)
//     {
//         intx::be::store(topics[i].bytes, state.stack[state.stack_ptr]);
//         state.stack_ptr--;
//     }

//     state.host->host->emit_log(state.host, &state.msg->destination, &state.memory[o], s,
//         topics.data(), static_cast<size_t>(number));
// }

// void op_log_0(execution_state& state, instr_argument) noexcept
// {
//     op_log(state, 0);
// }

// void op_log_1(execution_state& state, instr_argument) noexcept
// {
//     op_log(state, 1);
// }

// void op_log_2(execution_state& state, instr_argument) noexcept
// {
//     op_log(state, 2);
// }

// void op_log_3(execution_state& state, instr_argument) noexcept
// {
//     op_log(state, 3);
// }

// void op_log_4(execution_state& state, instr_argument) noexcept
// {
//     op_log(state, 4);
// }

// void op_invalid(execution_state& state, instr_argument) noexcept
// {
//     state.run = false;
//     state.status = EVMC_INVALID_INSTRUCTION;
// }

// void op_return(execution_state& state, instr_argument) noexcept
// {
//     auto offset = state.stack[state.stack_ptr];
//     auto size = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, offset, size))
//         return;

//     state.run = false;
//     state.output_offset = static_cast<size_t>(offset);
//     state.output_size = static_cast<size_t>(size);
// }

// void op_revert(execution_state& state, instr_argument) noexcept
// {
//     auto offset = state.stack[state.stack_ptr];
//     auto size = state.stack[state.stack_ptr - 1];

//     if (!check_memory(state, offset, size))
//         return;

//     state.run = false;
//     state.status = EVMC_REVERT;
//     state.output_offset = static_cast<size_t>(offset);
//     state.output_size = static_cast<size_t>(size);
// }

// void op_call(execution_state& state, instr_argument arg) noexcept
// {
//     auto gas = state.stack[state.stack_ptr];

//     uint8_t data[32];
//     intx::be::store(data, state.stack[state.stack_ptr - 1]);
//     auto dst = evmc_address{};
//     std::memcpy(dst.bytes, &data[12], sizeof(dst));

//     auto value = state.stack[state.stack_ptr - 2];
//     auto input_offset = state.stack[state.stack_ptr - 3]; // state.stack[state.stack_ptr - 3];
//     auto input_size = state.stack[state.stack_ptr - 4];
//     auto output_offset = state.stack[state.stack_ptr - 5];
//     auto output_size = state.stack[state.stack_ptr - 6];

//     state.stack_ptr -= 6;
//     state.stack[state.stack_ptr] = 0;

//     if (!check_memory(state, input_offset, input_size))
//         return;

//     if (!check_memory(state, output_offset, output_size))
//         return;


//     auto msg = evmc_message{};
//     msg.kind = arg.call_kind;
//     msg.flags = state.msg->flags;
//     intx::be::store(msg.value.bytes, value);

//     auto correction = state.current_block_cost - arg.number;
//     auto gas_left = state.gas_left + correction;

//     auto cost = 0;
//     auto has_value = value != 0;
//     if (has_value)
//     {
//         if (arg.call_kind == EVMC_CALL && state.msg->flags & EVMC_STATIC)
//         {
//             state.run = false;
//             state.status = EVMC_STATIC_MODE_VIOLATION;
//             return;
//         }
//         cost += 9000;
//     }

//     if (arg.call_kind == EVMC_CALL && (has_value || state.rev < EVMC_SPURIOUS_DRAGON))
//     {
//         if (!state.host->host->account_exists(state.host, &dst))
//             cost += 25000;
//     }

//     state.gas_left -= cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     msg.gas = std::numeric_limits<int64_t>::max();
//     if (gas < msg.gas)
//         msg.gas = static_cast<int64_t>(gas);

//     gas_left -= cost;

//     if (state.rev >= EVMC_TANGERINE_WHISTLE)
//         msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
//     else if (msg.gas > gas_left)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     state.return_data.clear();

//     if (state.msg->depth >= 1024)
//     {
//         if (has_value)
//             state.gas_left += 2300;  // Return unused stipend.
//         return;
//     }

//     msg.destination = dst;
//     msg.sender = state.msg->destination;
//     intx::be::store(msg.value.bytes, value);
//     msg.input_data = &state.memory[size_t(input_offset)];
//     msg.input_size = size_t(input_size);

//     msg.depth = state.msg->depth + 1;

//     if (has_value)
//     {
//         auto balance = state.host->host->get_balance(state.host, &state.msg->destination);
//         auto b = intx::be::uint256(balance.bytes);
//         if (b < value)
//         {
//             state.gas_left += 2300;  // Return unused stipend.
//             return;
//         }

//         msg.gas += 2300;  // Add stipend.
//     }

//     auto result = state.host->host->call(state.host, &msg);
//     state.return_data.assign(result.output_data, result.output_size);


//     state.stack[state.stack_ptr] = result.status_code == EVMC_SUCCESS;

//     std::memcpy(&state.memory[size_t(output_offset)], result.output_data,
//         std::min(size_t(output_size), result.output_size));

//     auto gas_used = msg.gas - result.gas_left;

//     if (result.release)
//         result.release(&result);

//     if (has_value)
//         gas_used -= 2300;

//     state.gas_left -= gas_used;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }
// }

// void op_delegatecall(execution_state& state, instr_argument arg) noexcept
// {
//     auto gas = state.stack[state.stack_ptr];

//     uint8_t data[32];
//     intx::be::store(data, state.stack[state.stack_ptr - 1]);
//     auto dst = evmc_address{};
//     std::memcpy(dst.bytes, &data[12], sizeof(dst));

//     auto input_offset = state.stack[state.stack_ptr - 2];
//     auto input_size = state.stack[state.stack_ptr - 3];
//     auto output_offset = state.stack[state.stack_ptr - 4];
//     auto output_size = state.stack[state.stack_ptr - 5];

//     state.stack_ptr -= 5;
//     state.stack[state.stack_ptr] = 0;

//     if (!check_memory(state, input_offset, input_size))
//         return;

//     if (!check_memory(state, output_offset, output_size))
//         return;

//     auto msg = evmc_message{};
//     msg.kind = EVMC_DELEGATECALL;

//     auto correction = state.current_block_cost - arg.number;
//     auto gas_left = state.gas_left + correction;

//     // TEST: Gas saturation for big gas values.
//     msg.gas = std::numeric_limits<int64_t>::max();
//     if (gas < msg.gas)
//         msg.gas = static_cast<int64_t>(gas);

//     if (state.rev >= EVMC_TANGERINE_WHISTLE)
//         msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
//     else if (msg.gas > gas_left)  // TEST: gas_left vs state.gas_left.
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     if (state.msg->depth >= 1024)
//         return;

//     msg.depth = state.msg->depth + 1;
//     msg.flags = state.msg->flags;
//     msg.destination = dst;
//     msg.sender = state.msg->sender;
//     msg.value = state.msg->value;
//     msg.input_data = &state.memory[size_t(input_offset)];
//     msg.input_size = size_t(input_size);

//     auto result = state.host->host->call(state.host, &msg);
//     state.return_data.assign(result.output_data, result.output_size);

//     state.stack[state.stack_ptr] = result.status_code == EVMC_SUCCESS;

//     std::memcpy(&state.memory[size_t(output_offset)], result.output_data,
//         std::min(size_t(output_size), result.output_size));

//     auto gas_used = msg.gas - result.gas_left;

//     if (result.release)
//         result.release(&result);

//     state.gas_left -= gas_used;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }
// }

// void op_staticcall(execution_state& state, instr_argument arg) noexcept
// {
//     auto gas = state.stack[state.stack_ptr];

//     uint8_t data[32];
//     intx::be::store(data, state.stack[state.stack_ptr - 1]);
//     auto dst = evmc_address{};
//     std::memcpy(dst.bytes, &data[12], sizeof(dst));

//     auto input_offset = state.stack[state.stack_ptr - 2];
//     auto input_size = state.stack[state.stack_ptr - 3];
//     auto output_offset = state.stack[state.stack_ptr - 4];
//     auto output_size = state.stack[state.stack_ptr - 5];

//     state.stack_ptr -= 5;
//     state.stack[state.stack_ptr] = 0;

//     if (!check_memory(state, input_offset, input_size))
//         return;

//     if (!check_memory(state, output_offset, output_size))
//         return;

//     if (state.msg->depth >= 1024)
//         return;

//     auto msg = evmc_message{};
//     msg.kind = EVMC_CALL;
//     msg.flags |= EVMC_STATIC;

//     msg.depth = state.msg->depth + 1;

//     auto correction = state.current_block_cost - arg.number;
//     auto gas_left = state.gas_left + correction;

//     msg.gas = std::numeric_limits<int64_t>::max();
//     if (gas < msg.gas)
//         msg.gas = static_cast<int64_t>(gas);

//     msg.gas = std::min(msg.gas, gas_left - gas_left / 64);

//     msg.destination = dst;
//     msg.sender = state.msg->destination;
//     msg.input_data = &state.memory[size_t(input_offset)];
//     msg.input_size = size_t(input_size);

//     auto result = state.host->host->call(state.host, &msg);
//     state.return_data.assign(result.output_data, result.output_size);
//     state.stack[state.stack_ptr] = result.status_code == EVMC_SUCCESS;

//     std::memcpy(&state.memory[size_t(output_offset)], result.output_data,
//         std::min(size_t(output_size), result.output_size));

//     auto gas_used = msg.gas - result.gas_left;

//     if (result.release)
//         result.release(&result);

//     state.gas_left -= gas_used;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }
// }

// void op_create(execution_state& state, instr_argument arg) noexcept
// {
//     if (state.msg->flags & EVMC_STATIC)
//     {
//         // TODO: Implement static mode violation in analysis.
//         state.run = false;
//         state.status = EVMC_STATIC_MODE_VIOLATION;
//         return;
//     }

//     auto endowment = state.stack[state.stack_ptr];
//     auto init_code_offset = state.stack[state.stack_ptr - 1];
//     auto init_code_size = state.stack[state.stack_ptr - 2];

//     state.stack_ptr -= 2;
//     state.stack[state.stack_ptr] = 0;

//     if (!check_memory(state, init_code_offset, init_code_size))
//         return;

//     state.return_data.clear();

//     if (state.msg->depth >= 1024)
//         return;

//     if (endowment != 0)
//     {
//         auto balance = intx::be::uint256(
//             state.host->host->get_balance(state.host, &state.msg->destination).bytes);
//         if (balance < endowment)
//             return;
//     }

//     auto msg = evmc_message{};

//     auto correction = state.current_block_cost - arg.number;
//     msg.gas = state.gas_left + correction;
//     if (state.rev >= EVMC_TANGERINE_WHISTLE)
//         msg.gas = msg.gas - msg.gas / 64;

//     msg.kind = EVMC_CREATE;
//     msg.input_data = &state.memory[size_t(init_code_offset)];
//     msg.input_size = size_t(init_code_size);
//     msg.sender = state.msg->destination;
//     msg.depth = state.msg->depth + 1;
//     intx::be::store(msg.value.bytes, endowment);

//     auto result = state.host->host->call(state.host, &msg);
//     state.return_data.assign(result.output_data, result.output_size);
//     if (result.status_code == EVMC_SUCCESS)
//     {
//         uint8_t data[32] = {};
//         std::memcpy(&data[12], &result.create_address, sizeof(result.create_address));
//         state.stack[state.stack_ptr] = intx::be::uint256(data);
//     }

//     auto gas_used = msg.gas - result.gas_left;

//     if (result.release)
//         result.release(&result);

//     state.gas_left -= gas_used;
//     if (state.gas_left < 0)
//     {
//         // FIXME: This cannot happen.
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//     }
// }

// void op_create2(execution_state& state, instr_argument arg) noexcept
// {
//     if (state.msg->flags & EVMC_STATIC)
//     {
//         // TODO: Implement static mode violation in analysis.
//         state.run = false;
//         state.status = EVMC_STATIC_MODE_VIOLATION;
//         return;
//     }

//     auto endowment = state.stack[state.stack_ptr];
//     auto init_code_offset = state.stack[state.stack_ptr - 1];
//     auto init_code_size = state.stack[state.stack_ptr - 2];
//     auto salt = state.stack[state.stack_ptr - 3];

//     state.stack_ptr -= 3;
//     state.stack[state.stack_ptr] = 0;

//     if (!check_memory(state, init_code_offset, init_code_size))
//         return;

//     auto salt_cost = ((int64_t(init_code_size) + 31) / 32) * 6;
//     state.gas_left -= salt_cost;
//     if (state.gas_left < 0)
//     {
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//         return;
//     }

//     state.return_data.clear();

//     if (state.msg->depth >= 1024)
//         return;

//     if (endowment != 0)
//     {
//         auto balance = intx::be::uint256(
//             state.host->host->get_balance(state.host, &state.msg->destination).bytes);
//         if (balance < endowment)
//             return;
//     }

//     auto msg = evmc_message{};

//     // TODO: Only for TW+. For previous check g <= gas_left.
//     auto correction = state.current_block_cost - arg.number;
//     auto gas = state.gas_left + correction;
//     msg.gas = gas - gas / 64;

//     msg.kind = EVMC_CREATE2;
//     msg.input_data = &state.memory[size_t(init_code_offset)];
//     msg.input_size = size_t(init_code_size);
//     msg.sender = state.msg->destination;
//     msg.depth = state.msg->depth + 1;
//     intx::be::store(msg.create2_salt.bytes, salt);
//     intx::be::store(msg.value.bytes, endowment);

//     auto result = state.host->host->call(state.host, &msg);
//     state.return_data.assign(result.output_data, result.output_size);
//     if (result.status_code == EVMC_SUCCESS)
//     {
//         uint8_t data[32] = {};
//         std::memcpy(&data[12], &result.create_address, sizeof(result.create_address));
//         state.stack[state.stack_ptr] = intx::be::uint256(data);
//     }

//     auto gas_used = msg.gas - result.gas_left;

//     if (result.release)
//         result.release(&result);

//     state.gas_left -= gas_used;
//     if (state.gas_left < 0)
//     {
//         // FIXME: This cannot happen.
//         state.run = false;
//         state.status = EVMC_OUT_OF_GAS;
//     }
// }

// void op_undefined(execution_state& state, instr_argument) noexcept
// {
//     state.run = false;
//     state.status = EVMC_UNDEFINED_INSTRUCTION;
// }

// void op_selfdestruct(execution_state& state, instr_argument) noexcept
// {
//     if (state.msg->flags & EVMC_STATIC)
//     {
//         // TODO: Implement static mode violation in analysis.
//         state.run = false;
//         state.status = EVMC_STATIC_MODE_VIOLATION;
//         return;
//     }

//     uint8_t data[32];
//     intx::be::store(data, state.stack[state.stack_ptr]);
//     evmc_address addr;
//     std::memcpy(addr.bytes, &data[12], sizeof(addr));

//     if (state.rev >= EVMC_TANGERINE_WHISTLE)
//     {
//         auto check_existance = true;

//         if (state.rev >= EVMC_SPURIOUS_DRAGON)
//         {
//             auto balance = state.host->host->get_balance(state.host, &state.msg->destination);
//             check_existance = !is_zero(balance);
//         }

//         if (check_existance)
//         {
//             // After EIP150 hard fork charge additional cost of sending
//             // ethers to non-existing account.
//             bool exists = state.host->host->account_exists(state.host, &addr);
//             if (!exists)
//             {
//                 state.gas_left -= 25000;
//                 if (state.gas_left < 0)
//                 {
//                     state.run = false;
//                     state.status = EVMC_OUT_OF_GAS;
//                     return;
//                 }
//             }
//         }
//     }

//     state.host->host->selfdestruct(state.host, &state.msg->destination, &addr);
//     state.run = false;
// }