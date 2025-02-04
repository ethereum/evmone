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
    evmc::bytes32 b;
};

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

    "beve address"_test = [] {
        [[maybe_unused]] const evmc::address a{};
        std::string s;
        expect(!glz::write_beve(a, s));
        expect(s.size() == 22_i);
    };

    "beve"_test = [] {
        fzz::Block v;
        [[maybe_unused]] const evmc::address a{};
        std::string s;
        expect(!glz::write_beve(v, s));
        expect(s.size() == 62_i);

        // S z;
        // expect(!glz::read_beve(z, s));
        // expect(z.a == v.a);
    };

    return 0;
}
