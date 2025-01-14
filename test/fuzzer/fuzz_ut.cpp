#include <evmc/evmc.hpp>
#include <glaze/glaze.hpp>
#include <boost/ut.hpp>

struct Test
{
    std::unordered_map<std::string, unsigned> s;
};

int main()
{
    using namespace boost::ut;

    "escape_control_characters"_test = [] {
        Test t;
        t.s["\001"] = 0;
        std::string buf;
        const auto write_ec = glz::write_json(t, buf);
        expect(!write_ec);
        expect(buf != "{\"s\":{\"\001\":0}}") << buf;

        const auto read_ec = glz::read_json(t, buf);
        expect(!read_ec) << glz::format_error(read_ec, buf);
    };

    return 0;
}
