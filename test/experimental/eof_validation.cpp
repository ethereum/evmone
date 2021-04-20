
#include <doctest/doctest.h>
#include <evmc/hex.hpp>
#include <variant>
#include <vector>

namespace eof
{
using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;

constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC[] = {0xa6, 0x1c};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;

enum class error_code
{
    success,
    starts_with_format,
    eof_version_mismatch,
    eof_version_unknown,

    incomplete_section_size,
    code_section_missing,
    unknown_section_id,
    zero_section_size,
    section_headers_not_terminated,
    invalid_section_bodies_size,

    initcode_failure,
    impossible,
};

struct ExecutionMock
{
    std::variant<bytes, error_code> execution_result;

    std::variant<bytes, error_code> execute([[maybe_unused]] bytes_view code)
    {
        return execution_result;
    }
};

int determine_eof_version(bytes_view code);
error_code validate(bytes_view code, int expected_version);
error_code validate_eof0(bytes_view code);
error_code validate_eof1(bytes_view code_without_prefix);
std::variant<bytes, error_code> create_contract_v1(
    ExecutionMock& ee, bytes_view initcode, int eof_version);
std::variant<bytes, error_code> create_contract_v2(
    ExecutionMock& ee, bytes_view initcode, int eof_version);
std::variant<bytes, error_code> execute_create_tx_v1(ExecutionMock& ee, bytes_view initcode);
std::variant<bytes, error_code> execute_create_tx_v2(ExecutionMock& ee, bytes_view initcode);

/// Determine the EOF version of the code by inspecting code's EOF prefix.
/// If the prefix is missing or invalid, the 0 is returned meaning legacy code.
int determine_eof_version(bytes_view code)
{
    return (code.size() >= 4 && code[0] == FORMAT && code[1] == MAGIC[0] && code[2] == MAGIC[1]) ?
               code[3] :
               0;
}

error_code validate(bytes_view code, int expected_version)
{
    const auto version = determine_eof_version(code);
    if (version != expected_version)
        return error_code::eof_version_mismatch;

    auto code_without_prefix = code;
    code_without_prefix.remove_prefix(4);
    switch (version)
    {
    default:
        return error_code::eof_version_unknown;
    case 0:
        return validate_eof0(code);
    case 1:
        return validate_eof1(code_without_prefix);
    }
}

error_code validate_eof0(bytes_view code)
{
    return (code.empty() || code[0] != FORMAT) ? error_code::success :
                                                 error_code::starts_with_format;
}

error_code validate_eof1(bytes_view code_without_prefix)
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id;
    int section_sizes[3] = {0, 0, 0};
    auto it = code_without_prefix.begin();
    while (it != code_without_prefix.end() && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it;
            switch (section_id)
            {
            case TERMINATOR:
                if (section_sizes[CODE_SECTION] == 0)
                    return error_code::code_section_missing;
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_sizes[CODE_SECTION] == 0)
                    return error_code::code_section_missing;
                [[fallthrough]];
            case CODE_SECTION:
                state = State::section_size;
                break;
            default:
                return error_code::unknown_section_id;
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it;
            ++it;
            if (it == code_without_prefix.end())
                return error_code::incomplete_section_size;
            const auto size_lo = *it;
            const auto section_size = (size_hi << 8) | size_lo;
            if (section_size == 0)
                return error_code::zero_section_size;

            section_sizes[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return error_code::impossible;
        }

        ++it;
    }

    if (state != State::terminated)
        return error_code::section_headers_not_terminated;

    const auto section_bodies_size = section_sizes[CODE_SECTION] + section_sizes[DATA_SECTION];
    const auto remaining_code_size = code_without_prefix.end() - it;
    if (section_bodies_size != remaining_code_size)
        return error_code::invalid_section_bodies_size;

    return error_code::success;
}

/// The core implementation of CREATE/CREATE2 instructions.
/// This is "generic/abstract" variant where initcode is always validated, including legacy code.
/// This is fine for EOF0 because there initcode starting with FORMAT is invalid, but the
/// execution would fail anyway.
std::variant<bytes, error_code> create_contract_v1(
    ExecutionMock& ee, bytes_view initcode, int eof_version)
{
    const auto err1 = validate(initcode, eof_version);
    if (err1 != error_code::success)
        return err1;

    const auto result = ee.execute(initcode);
    if (auto err2 = std::get_if<error_code>(&result))
        return *err2;

    const auto code = std::get<bytes>(result);
    const auto err3 = validate(code, eof_version);
    if (err3 != error_code::success)
        return err3;

    return code;
}

/// The core implementation of CREATE/CREATE2 instructions.
/// This is "minimal" variant where initcode is only validated for EOF1+.
std::variant<bytes, error_code> create_contract_v2(
    ExecutionMock& ee, bytes_view initcode, int eof_version)
{
    if (eof_version > 0)
    {
        // initcode validation is only required for EOF1+.
        const auto err1 = validate(initcode, eof_version);
        if (err1 != error_code::success)
            return err1;
    }

    const auto result = ee.execute(initcode);
    if (auto err2 = std::get_if<error_code>(&result))
        return *err2;

    const auto code = std::get<bytes>(result);
    const auto err3 = validate(code, eof_version);
    if (err3 != error_code::success)
        return err3;

    return code;
}

std::variant<bytes, error_code> execute_create_tx_v1(ExecutionMock& ee, bytes_view initcode)
{
    return create_contract_v1(ee, initcode, determine_eof_version(initcode));
}

std::variant<bytes, error_code> execute_create_tx_v2(ExecutionMock& ee, bytes_view initcode)
{
    return create_contract_v2(ee, initcode, determine_eof_version(initcode));
}
}  // namespace eof

using namespace eof;
using evmc::from_hex;

TEST_CASE("validate empty code")
{
    CHECK(validate({}, 0) == error_code::success);
    CHECK(validate({}, 1) == error_code::eof_version_mismatch);
    CHECK(validate({}, 2) == error_code::eof_version_mismatch);
}

TEST_CASE("reject code starting with FORMAT in intermediate period")
{
    CHECK(validate(from_hex("00"), 0) == error_code::success);
    CHECK(validate(from_hex("FE"), 0) == error_code::success);
    CHECK(validate(from_hex("EF"), 0) == error_code::starts_with_format);
}

TEST_CASE("validate EOF prefix")
{
    CHECK(validate(from_hex("EFA61C01"), 1) == error_code::section_headers_not_terminated);

    CHECK(validate(from_hex(""), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EF"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA6"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61C"), 1) == error_code::eof_version_mismatch);

    CHECK(validate(from_hex("EEA61C01"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA71C01"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61D01"), 1) == error_code::eof_version_mismatch);
}

TEST_CASE("validate EOF version")
{
    CHECK(validate(from_hex("EFA61C01"), 1) == error_code::section_headers_not_terminated);
    CHECK(validate(from_hex("EFA61C02"), 2) == error_code::eof_version_unknown);
    CHECK(validate(from_hex("EFA61CFF"), 0xff) == error_code::eof_version_unknown);

    CHECK(validate(from_hex("EFA61C01"), 2) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61C02"), 1) == error_code::eof_version_mismatch);
}

TEST_CASE("minimal valid EOF1 code")
{
    CHECK(validate(from_hex("EFA61C01 010001 00 FE"), 1) == error_code::success);
}

TEST_CASE("minimal valid EOF1 code with data")
{
    CHECK(validate(from_hex("EFA61C01 010001 020001 00 FE DA"), 1) == error_code::success);
}

TEST_CASE("EOF1 code section missing")
{
    CHECK(validate(from_hex("EFA61C01 00"), 1) == error_code::code_section_missing);
    CHECK(validate(from_hex("EFA61C01 020001 DA"), 1) == error_code::code_section_missing);
}

TEST_CASE("create legacy contract - success")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{0};

    CHECK(std::get<bytes>(create_contract_v1(mock, initcode, 0)) == bytes{0});
    CHECK(std::get<bytes>(create_contract_v2(mock, initcode, 0)) == bytes{0});
}

TEST_CASE("legacy create transaction - success")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{0};

    CHECK(std::get<bytes>(execute_create_tx_v1(mock, initcode)) == bytes{0});
    CHECK(std::get<bytes>(execute_create_tx_v2(mock, initcode)) == bytes{0});
}

TEST_CASE("legacy create transaction - initcode failure")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;

    CHECK(
        std::get<error_code>(execute_create_tx_v1(mock, initcode)) == error_code::initcode_failure);
    CHECK(
        std::get<error_code>(execute_create_tx_v2(mock, initcode)) == error_code::initcode_failure);
}

TEST_CASE("legacy create transaction - code starts with FORMAT")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{FORMAT, 0};

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::starts_with_format);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, initcode)) ==
          error_code::starts_with_format);
}

TEST_CASE("legacy create transaction - initcode starts with FORMAT")
{
    const auto initcode = bytes{FORMAT};
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;  // FORMAT opcode aborts execution.

    // Here we have different error codes depending on initcode being validated or not.
    // But the end results is the same: create transaction fails.
    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::starts_with_format);
    CHECK(
        std::get<error_code>(execute_create_tx_v2(mock, initcode)) == error_code::initcode_failure);
}

TEST_CASE("legacy create transaction - EOF version mismatch")
{
    const auto initcode = bytes{};
    ExecutionMock mock;
    mock.execution_result = from_hex("EFA61C01 010001 00 FE");  // EOF1 code.

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, initcode)) ==
          error_code::eof_version_mismatch);
}

TEST_CASE("EOF1 create transaction - success")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof1_code;

    CHECK(std::get<bytes>(execute_create_tx_v1(mock, eof1_code)) == eof1_code);
    CHECK(std::get<bytes>(execute_create_tx_v2(mock, eof1_code)) == eof1_code);
}

TEST_CASE("EOF1 create transaction - invalid initcode")
{
    const auto eof2_code = from_hex("EFA61C02");
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof1_code;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof2_code)) ==
          error_code::eof_version_unknown);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof2_code)) ==
          error_code::eof_version_unknown);
}

TEST_CASE("EOF1 create transaction - initcode failure")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::initcode_failure);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::initcode_failure);
}

TEST_CASE("EOF1 create transaction - EOF version mismatch")
{
    const auto eof2_code = from_hex("EFA61C02");
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof2_code;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
}

TEST_CASE("EOF1 create transaction - legacy code")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = bytes{};  // Legacy code

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
}

TEST_CASE("EOF1 create transaction - invalid code")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    const auto eof1_code_invalid = from_hex("EFA61C01");
    ExecutionMock mock;
    mock.execution_result = eof1_code_invalid;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::section_headers_not_terminated);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::section_headers_not_terminated);
}
