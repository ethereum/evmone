#include "format.hpp"
#include <glaze/glaze.hpp>
#include <iostream>

namespace glz::detail
{
template <>
struct from<JSON, evmc::address>
{
    template <auto Opts, is_context Ctx>
    static void op(evmc::address& v, Ctx&& ctx, auto&&... args)
    {
        char buffer[sizeof(evmc::address) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, ctx, args...);
        const auto tmp = evmc::from_hex<evmc::address>(str);

        // This can be invalid hex string (e.g. truncated by -max_len).
        if (tmp.has_value())
            v = *tmp;
        else
            ctx.error = error_code::elements_not_convertible_to_design;
    }
};

template <>
struct to<JSON, evmc::address>
{
    template <auto Opts>
    static void op(const evmc::address& addr, auto&&... args) noexcept
    {
        const auto str = evmc::hex(addr);
        write<JSON>::op<Opts>(str, args...);
    }
};

template <>
struct from<JSON, evmc::bytes32>
{
    template <auto Opts, is_context Ctx>
    static void op(evmc::bytes32& v, Ctx&& ctx, auto&&... args)
    {
        // Convert a hex string to bytes.
        char buffer[sizeof(evmc::bytes32) * 2]{};
        std::string_view str{buffer, sizeof(buffer)};
        read<JSON>::op<Opts>(str, ctx, args...);
        const auto tmp = evmc::from_hex<evmc::bytes32>(str);

        // This can be invalid hex string (e.g. truncated by -max_len).
        if (tmp.has_value())
            v = *tmp;
        else
            ctx.error = error_code::elements_not_convertible_to_design;
    }
};

template <>
struct to<JSON, evmc::bytes32>
{
    template <auto Opts>
    static void op(const evmc::bytes32& v, auto&&... args) noexcept
    {
        const auto str = evmc::hex(v);
        write<JSON>::op<Opts>(str, args...);
    }
};

template <>
struct from<BEVE, evmc::address>
{
    template <auto Opts>
    static void op(evmc::address& v, auto&&... args)
    {
        read<BEVE>::op<Opts>(v.bytes, args...);
    }
};

template <>
struct to<BEVE, evmc::address>
{
    template <auto Opts>
    static void op(const evmc::address& v, auto&&... args) noexcept
    {
        write<BEVE>::op<Opts>(v.bytes, args...);
    }
};

template <>
struct from<BEVE, evmc::bytes32>
{
    template <auto Opts>
    static void op(evmc::bytes32& v, auto&&... args)
    {
        read<BEVE>::op<Opts>(v.bytes, args...);
    }
};

template <>
struct to<BEVE, evmc::bytes32>
{
    template <auto Opts>
    static void op(const evmc::bytes32& v, auto&&... args) noexcept
    {
        write<BEVE>::op<Opts>(v.bytes, args...);
    }
};
}  // namespace glz::detail


namespace fzz
{
namespace
{
constexpr glz::opts OPTS{
    .null_terminated = false,
    .error_on_unknown_keys = false,

    // Require the input to be minified. This is supposed to make the reading faster, but looks like
    // it makes it slower. Investigate later.
    .minified = true,
};
}

std::optional<Test> deserialize(std::span<const uint8_t> data)
{
    fzz::Test test;
    if (const auto ec = glz::read<OPTS>(test, data))
    {
        switch (ec.ec)
        {
            // Expected errors:
        case glz::error_code::no_read_input:
        case glz::error_code::unexpected_end:
        case glz::error_code::expected_quote:
        case glz::error_code::end_reached:
        case glz::error_code::expected_brace:  // minified
        case glz::error_code::expected_colon:  // minified
        case glz::error_code::expected_comma:  // minified
        case glz::error_code::elements_not_convertible_to_design:
            return {};
        default:
            std::cerr << "JSON read error: " << glz::format_error(ec, data) << '\n';
            __builtin_trap();
        }
    }
    return test;
}

size_t serialize(const Test& test, std::span<uint8_t> data)
{
    std::string out;
    if (const auto write_ec = glz::write<OPTS>(test, out))
    {
        std::cerr << "JSON write error: " << glz::format_error(write_ec, out) << '\n';
        __builtin_trap();
    }
    if (out.size() + 1 > data.size())
    {
        // std::cerr << "too big\n";
        return 0;
    }
    std::memcpy(data.data(), out.c_str(), out.size() + 1);
    return out.size();
}
}  // namespace fzz
