
#include <doctest/doctest.h>
#include <evmc/hex.hpp>

namespace eof
{
bool validate();

bool validate()
{
    return false;
}
}  // namespace eof

using namespace eof;

TEST_CASE("dumb test")
{
    WARN(validate());
}
