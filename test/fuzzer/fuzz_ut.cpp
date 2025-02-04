#include "fuzz_types.hpp"
#include <glaze/beve.hpp>
#include <glaze/json.hpp>
#include <boost/ut.hpp>

struct Test
{
    std::unordered_map<std::string, unsigned> s;
};

struct S
{
    evmc::address a;

    // void read_a(const std::string& s) {
    //     assert(s.size() == 20);
    //     std::memcpy(a.bytes, s.data(), 20);
    // }
    //
    // std::array<uint8_t, 20> write_a() {
    //     return std::bit_cast<std::array<uint8_t, 20>>(a);
    // }
};

// template <>
// struct glz::meta<S> {
//     static constexpr auto value = object("a", custom<&S::read_a, &S::write_a>);
// };

namespace glz::detail
{
template <>
struct from<BEVE, evmc::address>
{
    template <auto Opts>
    static void op(evmc::address& v, auto&&... args)
    {
        read<JSON>::op<Opts>(v.bytes, args...);
    }
};

template <>
struct to<BEVE, evmc::address>
{
    template <auto Opts>
    static void op(const evmc::address& v, auto&&... args) noexcept
    {
        write<JSON>::op<Opts>(v.bytes, args...);
    }
};
}

int main()
{
    using namespace boost::ut;

    // "escape_control_characters"_test = [] {
    //     Test t;
    //     t.s["\001"] = 0;
    //     std::string buf;
    //     const auto write_ec = glz::write_json(t, buf);
    //     expect(!write_ec);
    //     expect(buf != "{\"s\":{\"\001\":0}}") << buf;
    //
    //     const auto read_ec = glz::read_json(t, buf);
    //     expect(!read_ec) << glz::format_error(read_ec, buf);
    // };

    "out_of_buf_read"_test = [] {
        const std::string_view data = R"({"x":"")";
        const auto heap_buf = std::make_unique_for_overwrite<char[]>(data.size());
        std::ranges::copy(data, heap_buf.get());
        const std::string_view buf{heap_buf.get(), data.size()};

        static constexpr glz::opts OPTS{
            .null_terminated = false,
            .error_on_unknown_keys = false,
            .minified = true,
        };

        struct {} t;
        const auto ec = glz::read<OPTS>(t, buf);
        expect(ec);
    };

    "beve"_test = [] {
        S v;
        v.a.bytes[3] = 43;
        [[maybe_unused]] const evmc::address a{};
        std::string s;
        expect(!glz::write_beve(v, s));
        expect(s.size() == 46_i);

        S z;
        expect(!glz::read_beve(z, s));
        expect(z.a == v.a);
    };

    return 0;
}
