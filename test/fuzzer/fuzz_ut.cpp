// #include "fuzz_types.hpp"
#include <glaze/json.hpp>
#include <boost/ut.hpp>

struct Test
{
    std::unordered_map<std::string, unsigned> s;
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

    return 0;
}
