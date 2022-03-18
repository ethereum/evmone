// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

#include <cstring>
#include <iostream>
#include <limits>

inline std::ostream& operator<<(std::ostream& os, const evmc_address& addr)
{
    return os << hex({addr.bytes, sizeof(addr.bytes)});
}

inline std::ostream& operator<<(std::ostream& os, const evmc_bytes32& v)
{
    return os << hex({v.bytes, sizeof(v.bytes)});
}

inline std::ostream& operator<<(std::ostream& os, const bytes_view& v)
{
    return os << hex(v);
}

[[clang::always_inline]] inline void assert_true(
    bool cond, const char* cond_str, const char* file, int line)
{
    if (!cond)
    {
        std::cerr << "ASSERTION FAILED: \"" << cond_str << "\"\n\tin " << file << ":" << line
                  << std::endl;
        __builtin_trap();
    }
}
#define ASSERT(COND) assert_true(COND, #COND, __FILE__, __LINE__)

template <typename T1, typename T2>
[[clang::always_inline]] inline void assert_eq(
    const T1& a, const T2& b, const char* a_str, const char* b_str, const char* file, int line)
{
    if (!(a == b))
    {
        std::cerr << "ASSERTION FAILED: \"" << a_str << " == " << b_str << "\"\n\twith " << a
                  << " != " << b << "\n\tin " << file << ":" << line << std::endl;
        __builtin_trap();
    }
}

#define ASSERT_EQ(A, B) assert_eq(A, B, #A, #B, __FILE__, __LINE__)

static auto print_input = std::getenv("PRINT");

/// The reference VM.
static auto ref_vm = evmc::VM{evmc_create_evmone(), {{"O", "0"}}};

static evmc::VM external_vms[] = {
    evmc::VM{evmc_create_evmone(), {{"O", "2"}}},
};


class FuzzHost : public evmc::MockedHost
{
public:
    uint8_t gas_left_factor = 0;

    evmc::result call(const evmc_message& msg) noexcept override
    {
        auto result = MockedHost::call(msg);

        // Set gas_left.
        if (gas_left_factor == 0)
            result.gas_left = 0;
        else if (gas_left_factor == 1)
            result.gas_left = msg.gas;
        else
            result.gas_left = msg.gas / (gas_left_factor + 3);

        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        {
            // Use the output to fill the create address.
            // We still keep the output to check if VM is going to ignore it.
            std::memcpy(result.create_address.bytes, result.output_data,
                std::min(sizeof(result.create_address), result.output_size));
        }

        return result;
    }
};

struct FuzzEnv
{
    evmc_revision rev;
    evmc_message msg;
    FuzzHost host;
};

inline evmc::uint256be generate_interesting_value(uint8_t b) noexcept
{
    const auto s = (b >> 6) & 0b11;
    const auto fill = (b >> 5) & 0b1;
    const auto above = (b >> 4) & 0b1;
    const auto val = b & 0b1111;

    auto z = evmc::uint256be{};

    const size_t size = s == 0 ? 1 : 1 << (s + 2);

    if (fill)
    {
        for (auto i = sizeof(z) - size; i < sizeof(z); ++i)
            z.bytes[i] = 0xff;
    }

    if (above)
        z.bytes[sizeof(z) - size % sizeof(z) - 1] ^= val;
    else
        z.bytes[sizeof(z) - size] ^= val << 4;

    return z;
}

inline evmc::address generate_interesting_address(uint8_t b) noexcept
{
    const auto s = (b >> 6) & 0b11;
    const auto fill = (b >> 5) & 0b1;
    const auto above = (b >> 4) & 0b1;
    const auto val = b & 0b1111;

    auto z = evmc::address{};

    const size_t size = s == 3 ? 20 : 1 << s;

    if (fill)
    {
        for (auto i = sizeof(z) - size; i < sizeof(z); ++i)
            z.bytes[i] = 0xff;
    }

    if (above)
        z.bytes[sizeof(z) - size % sizeof(z) - 1] ^= val;
    else
        z.bytes[sizeof(z) - size] ^= val << 4;

    return z;
}

/// Creates the block number value from 8-bit value.
/// The result is still quite small because block number affects blockhash().
inline int expand_block_number(uint8_t x) noexcept
{
    return x * 97;
}

inline int64_t expand_block_timestamp(uint8_t x) noexcept
{
    // TODO: If timestamp is -1 Aleth and evmone disagrees how to convert it to uint256.
    return x < 255 ? int64_t{16777619} * x : std::numeric_limits<int64_t>::max();
}

inline int64_t expand_block_gas_limit(uint8_t x) noexcept
{
    return x == 0 ? 0 : std::numeric_limits<int64_t>::max() / x;
}

constexpr size_t min_required_size = 33;

class FuzzEnv2
{
    uint32_t gas_;
    uint8_t rev_;
    uint8_t input_size_;
    uint8_t kind_ : 1;
    uint8_t static_ : 1;
    uint8_t depth_ : 2;

public:
    uint8_t recipient_;
    uint8_t sender_;
    uint8_t value_;
    uint8_t create2_salt_;

private:
    [[maybe_unused]] uint8_t padding_[21];

    FuzzEnv2() = default;

public:
    static FuzzEnv2 load(const uint8_t* data) noexcept
    {
        FuzzEnv2 raw;
        __builtin_memcpy(&raw, data, sizeof(raw));

        FuzzEnv2 env{};
        env.gas_ = raw.gas_ & 0x3ffff;  // 18 bits
        env.rev_ = std::min<uint8_t>(raw.rev_ & 0b11111, EVMC_LATEST_STABLE_REVISION);
        env.input_size_ = raw.input_size_;
        env.kind_ = raw.kind_;
        env.static_ = raw.static_;
        env.depth_ = raw.depth_;

        return env;
    }

    static void normalize(uint8_t* data) noexcept
    {
        const auto env = load(data);
        __builtin_memcpy(data, &env, sizeof(env));
    }

    evmc_revision rev() const noexcept { return static_cast<evmc_revision>(rev_); }
    evmc_call_kind msg_kind() const noexcept { return kind_ == 0 ? EVMC_CALL : EVMC_CREATE; }
    evmc_flags msg_flags() const noexcept
    {
        return static_cast<evmc_flags>(static_ == 0 ? 0 : EVMC_STATIC);
    }
    int depth() const noexcept
    {
        const auto h = (depth_ >> 1) & 0b1;
        const auto l = depth_ & 0b1;
        return 1023 * h + l;  // 0, 1, 1023, 1024.
    }
    size_t input_size() const noexcept { return input_size_; }
    int64_t gas() const noexcept { return gas_; }
};
static_assert(sizeof(FuzzEnv2) == 32);

FuzzEnv populate_fuzz_env(const uint8_t* data, size_t data_size) noexcept
{
    const auto env = FuzzEnv2::load(data);

    FuzzEnv in{};

    const auto tx_gas_price_8bits = data[10];
    const auto tx_origin_8bits = data[11];
    const auto block_coinbase_8bits = data[12];
    const auto block_number_8bits = data[13];
    const auto block_timestamp_8bits = data[14];
    const auto block_gas_limit_8bits = data[15];
    const auto block_difficulty_8bits = data[16];
    const auto chainid_8bits = data[17];

    const auto account_balance_8bits = data[18];
    const auto account_storage_key1_8bits = data[19];
    const auto account_storage_key2_8bits = data[20];
    const auto account_codehash_8bits = data[21];
    // TODO: Add another account?

    const auto call_result_status_4bits = data[22] >> 4;
    const auto call_result_gas_left_factor_4bits = uint8_t(data[23] & 0b1111);

    in.rev = env.rev();

    data += 32;
    data_size -= 32;

    in.msg.kind = env.msg_kind();

    in.msg.flags = env.msg_flags();
    in.msg.depth = env.depth();

    in.msg.gas = env.gas();

    const auto input_size = std::min(env.input_size(), data_size / 2);
    const auto code_size = data_size - input_size;

    in.msg.recipient = generate_interesting_address(env.recipient_);
    in.msg.sender = generate_interesting_address(env.sender_);
    in.msg.input_size = input_size;
    in.msg.input_data = data + code_size;
    in.msg.value = generate_interesting_value(env.value_);

    // Should be ignored by VMs.
    in.msg.create2_salt = generate_interesting_value(env.create2_salt_);

    in.host.tx_context.tx_gas_price = generate_interesting_value(tx_gas_price_8bits);
    in.host.tx_context.tx_origin = generate_interesting_address(tx_origin_8bits);
    in.host.tx_context.block_coinbase = generate_interesting_address(block_coinbase_8bits);
    in.host.tx_context.block_number = expand_block_number(block_number_8bits);
    in.host.tx_context.block_timestamp = expand_block_timestamp(block_timestamp_8bits);
    in.host.tx_context.block_gas_limit = expand_block_gas_limit(block_gas_limit_8bits);
    in.host.tx_context.block_difficulty = generate_interesting_value(block_difficulty_8bits);
    in.host.tx_context.chain_id = generate_interesting_value(chainid_8bits);

    auto& account = in.host.accounts[in.msg.recipient];
    account.balance = generate_interesting_value(account_balance_8bits);
    const auto storage_key1 = generate_interesting_value(account_storage_key1_8bits);
    const auto storage_key2 = generate_interesting_value(account_storage_key2_8bits);
    account.storage[{}] = storage_key2;
    account.storage[storage_key1] = storage_key2;

    // Add dirty value as if it has been already modified in this transaction.
    account.storage[storage_key2] = {storage_key1, true};

    account.codehash = generate_interesting_value(account_codehash_8bits);
    account.code = {data, code_size};

    in.host.call_result.status_code = static_cast<evmc_status_code>(call_result_status_4bits);
    in.host.gas_left_factor = call_result_gas_left_factor_4bits;

    // Use 3/5 of the input from the and as the potential call output.
    const auto offset = in.msg.input_size * 2 / 5;
    in.host.call_result.output_data = &in.msg.input_data[offset];
    in.host.call_result.output_size = in.msg.input_size - offset;

    return in;
}

inline auto hex(const evmc_address& addr) noexcept
{
    return hex({addr.bytes, sizeof(addr)});
}

inline evmc_status_code check_and_normalize(evmc_status_code status) noexcept
{
    ASSERT(status >= 0);
    return status <= EVMC_REVERT ? status : EVMC_FAILURE;
}


extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int /*seed*/) noexcept
{
    if (max_size < min_required_size)
        return 0;

    size = std::min(size, min_required_size);
    size = LLVMFuzzerMutate(data, size, max_size);
    size = std::min(size, min_required_size);

    FuzzEnv2::normalize(data);

    if (data[3] != 0)
        __builtin_trap();

    if (data[4] > EVMC_LATEST_STABLE_REVISION)
        __builtin_trap();

    return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    if (data_size < min_required_size)
        return 0;

    auto in = populate_fuzz_env(data, data_size);

    if (in.rev > EVMC_LATEST_STABLE_REVISION)
        __builtin_trap();

    auto ref_host = in.host;  // Copy Host.
    const auto& code = ref_host.accounts[in.msg.recipient].code;

    if (print_input)
    {
        std::cout << "rev: " << int{in.rev} << "\n";
        std::cout << "depth: " << int{in.msg.depth} << "\n";
        std::cout << "code: " << hex(code) << "\n";
        std::cout << "decoded: " << decode(code, in.rev) << "\n";
        std::cout << "input: " << hex({in.msg.input_data, in.msg.input_size}) << "\n";
        std::cout << "account: " << hex(in.msg.recipient) << "\n";
        std::cout << "caller: " << hex(in.msg.sender) << "\n";
        std::cout << "value: " << in.msg.value << "\n";
        std::cout << "gas: " << in.msg.gas << "\n";
        std::cout << "balance: " << in.host.accounts[in.msg.recipient].balance << "\n";
        std::cout << "coinbase: " << in.host.tx_context.block_coinbase << "\n";
        std::cout << "difficulty: " << in.host.tx_context.block_difficulty << "\n";
        std::cout << "timestamp: " << in.host.tx_context.block_timestamp << "\n";
        std::cout << "chainid: " << in.host.tx_context.chain_id << "\n";
    }

    const auto ref_res = ref_vm.execute(ref_host, in.rev, in.msg, code.data(), code.size());
    const auto ref_status = check_and_normalize(ref_res.status_code);
    if (ref_status == EVMC_FAILURE)
        ASSERT_EQ(ref_res.gas_left, 0);

    for (auto& vm : external_vms)
    {
        auto host = in.host;  // Copy Host.
        const auto res = vm.execute(host, in.rev, in.msg, code.data(), code.size());

        const auto status = check_and_normalize(res.status_code);
        ASSERT_EQ(status, ref_status);
        ASSERT_EQ(res.gas_left, ref_res.gas_left);
        ASSERT_EQ(bytes_view(res.output_data, res.output_size),
            bytes_view(ref_res.output_data, ref_res.output_size));

        if (ref_status != EVMC_FAILURE)
        {
            ASSERT_EQ(ref_host.recorded_calls.size(), host.recorded_calls.size());

            for (size_t i = 0; i < ref_host.recorded_calls.size(); ++i)
            {
                const auto& m1 = ref_host.recorded_calls[i];
                const auto& m2 = host.recorded_calls[i];

                ASSERT_EQ(m1.kind, m2.kind);
                ASSERT_EQ(m1.flags, m2.flags);
                ASSERT_EQ(m1.depth, m2.depth);
                ASSERT_EQ(m1.gas, m2.gas);
                ASSERT_EQ(evmc::address{m1.recipient}, evmc::address{m2.recipient});
                ASSERT_EQ(evmc::address{m1.sender}, evmc::address{m2.sender});
                ASSERT_EQ(bytes_view(m1.input_data, m1.input_size),
                    bytes_view(m2.input_data, m2.input_size));
                ASSERT_EQ(evmc::uint256be{m1.value}, evmc::uint256be{m2.value});
                ASSERT_EQ(evmc::bytes32{m1.create2_salt}, evmc::bytes32{m2.create2_salt});
            }

            ASSERT(std::equal(ref_host.recorded_logs.begin(), ref_host.recorded_logs.end(),
                host.recorded_logs.begin(), host.recorded_logs.end()));

            ASSERT_EQ(ref_host.recorded_blockhashes.size(), host.recorded_blockhashes.size());
            ASSERT(std::equal(ref_host.recorded_blockhashes.begin(),
                ref_host.recorded_blockhashes.end(), host.recorded_blockhashes.begin(),
                host.recorded_blockhashes.end()));

            ASSERT(std::equal(ref_host.recorded_selfdestructs.begin(),
                ref_host.recorded_selfdestructs.end(), host.recorded_selfdestructs.begin(),
                host.recorded_selfdestructs.end()));

            // TODO: Enable account accesses check. Currently this is not possible because Aleth
            //       is doing additional unnecessary account existence checks in calls.
            // ASSERT(std::equal(ref_host.recorded_account_accesses.begin(),
            //     ref_host.recorded_account_accesses.end(), host.recorded_account_accesses.begin(),
            //     host.recorded_account_accesses.end()));
        }
    }

    return 0;
}
