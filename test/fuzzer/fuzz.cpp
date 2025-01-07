#include "../state/state.hpp"
#include <glaze/glaze.hpp>
#include <random>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size) noexcept;


template <>
struct glz::meta<evmc::address>
{
    using T = evmc::address;
    static constexpr auto value = object(&T::bytes);
};

namespace fzz
{
using RNG = std::minstd_rand;

struct Account
{
    uint32_t nonce = 0;
    uint32_t balance = 0;
    std::string code;
};

struct Tx
{
    uint8_t to = 0;
    std::string data;
};

struct Test
{
    std::unordered_map<evmc::address, Account> state;
    Tx tx;
};

void mutate(std::integral auto& value, RNG&)
{
    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&value), sizeof(value), sizeof(value));
}

void mutate(evmc::address& value, RNG&)
{
    LLVMFuzzerMutate(value.bytes, sizeof(value), sizeof(value));
}

template <typename T>
void mutate(std::vector<T>& v, RNG& rng)
{
    const auto index = rng() % (v.size() + 1);
    if (index == v.size())
        v.emplace_back();
    mutate(v[index], rng);
}

template <typename K, typename V>
void mutate(std::unordered_map<K, V>& v, RNG& rng)
{
    const auto index = rng() % (v.size() + 1);
    if (index == v.size())
        v.emplace();  // TODO: loop until successful insertion.
    else
    {
        auto it = v.begin();
        std::advance(it, index);
        mutate(it->second, rng);
    }
}

void mutate(std::string& value, RNG&)
{
    const auto cur_size = value.size();
    const auto max_size = std::max(cur_size * 4 / 3, 1uz);
    value.resize(max_size);
    const auto new_size =
        LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(value.data()), cur_size, max_size);
    value.resize(new_size);
}

template <typename T>
void mutate(T& value, RNG& rng)
{
    using R = glz::reflect<T>;
    const auto index = rng() % R::size;

    size_t c = 0;
    glz::for_each_field(value, [&](auto& field) {
        if (c == index)
        {
            mutate(field, rng);
        }
        ++c;
    });
}
}  // namespace fzz

static constexpr glz::opts OPTS{.null_terminated = false};


extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, uint32_t seed)
{
    fzz::RNG rng{seed};
    const std::string_view buffer{reinterpret_cast<const char*>(data), size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (!ec)
    {
        fzz::mutate(test, rng);
    }

    auto e = glz::write_json(test);
    if (e.has_value())
    {
        const auto& s = e.value();
        if (s.size() + 1 > max_size)
            return 0;
        std::memcpy(data, s.c_str(), s.size() + 1);
        return s.size();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const std::string_view buffer{reinterpret_cast<const char*>(data), data_size};

    fzz::Test test;
    const auto ec = glz::read<OPTS>(test, buffer);
    if (ec)
        return -1;

    evmone::state::Transaction tx;
    tx.data = evmone::bytes{test.tx.data.begin(), test.tx.data.end()};

    // evmone::state::validate_transaction()

    return 0;
}
