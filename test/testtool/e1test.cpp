
#include <glaze/glaze.hpp>

#include <iostream>
#include <map>

struct Tx
{
    std::string_view input;
};

static void load_tx()
{
    constexpr std::string_view buffer = R"({
        "input": "b0b1",
        "gas": "0x9091",
        "chainId": "0x5",
        "value": "0xe0e1",
        "sender": "a0a1",
        "gasPrice": "0x7071",
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    static constexpr auto opts = glz::opts{.error_on_unknown_keys = false};

    Tx tx;
    auto err = glz::read<opts>(tx, buffer);
    if (err)
    {
        std::cerr << "Failed to read Tx: " << glz::format_error(err, buffer);
    }
    else
    {
        std::cout << tx.input << std::endl;
    }
}

int main()
{
    load_tx();


    const auto buffer = R"({"a":1,"b":2})";

    auto s = glz::read_json<std::map<std::string_view, int>>(buffer);
    if (!s)
    {
        std::cerr << "Failed to read JSON: " << glz::format_error(s.error(), buffer);
        return 1;
    }
    if (s)  // check std::expected
    {
        s.value();  // s.value() is a my_struct populated from buffer
    }

    return 0;
}
