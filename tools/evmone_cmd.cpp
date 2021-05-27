#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <iostream>
#include <string_view>

int main(int argc, const char* argv[])
{
    using namespace std::literals;

    evmc::VM vm{evmc_create_evmone()};
    const auto rev = EVMC_BERLIN;
    const int64_t gas = 10000000;
    auto& out = std::cout;

    if (argc >= 4)
    {
        if (argv[1] == "--baseline"sv)
            vm.set_option("O", "0");
        else
            return -4;

        --argc;
        ++argv;
    }

    if (argc < 2)
    {
        std::cerr << "Code argument missing.";
        return -3;
    }

    const auto code_hex = std::string_view{argv[1]};
    const auto input_hex = (argc >= 3) ? std::string_view{argv[2]} : std::string_view{};

    out << "Executing on " << rev << " with " << gas << " gas limit\n";

    const auto code = evmc::from_hex(code_hex);
    const auto input = evmc::from_hex(input_hex);

    evmc::MockedHost host;

    evmc_message msg{};
    msg.gas = gas;
    msg.input_data = input.data();
    msg.input_size = input.size();

    evmc::bytes_view exec_code = code;
    out << "\n";

    const auto result = vm.execute(host, rev, msg, exec_code.data(), exec_code.size());

    const auto gas_used = msg.gas - result.gas_left;
    out << "Result:   " << result.status_code << "\nGas used: " << gas_used << "\n";

    if (result.status_code == EVMC_SUCCESS || result.status_code == EVMC_REVERT)
        out << "Output:   " << evmc::hex({result.output_data, result.output_size}) << "\n";

    return 0;
}
