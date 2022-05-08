// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "mpt.hpp"
#include "rlp.hpp"
#include <algorithm>
#include <cassert>

namespace evmone::state
{
namespace
{
/// The collection of nibbles (4-bit values) representing a path in a MPT.
struct Path
{
    size_t length;  // TODO: Can be converted to uint8_t.
    uint8_t nibbles[64]{};

    explicit Path(bytes_view key) noexcept : length{2 * key.size()}
    {
        assert(length <= std::size(nibbles));
        size_t i = 0;
        for (const auto b : key)
        {
            // static_cast is only needed in GCC <= 8.
            nibbles[i++] = static_cast<uint8_t>(b >> 4);
            nibbles[i++] = static_cast<uint8_t>(b & 0x0f);
        }
    }

    [[nodiscard]] Path tail(size_t pos) const noexcept
    {
        assert(pos <= length);
        Path p{{}};
        p.length = length - pos;
        std::copy_n(&nibbles[pos], p.length, p.nibbles);
        return p;
    }

    [[nodiscard]] Path head(size_t size) const noexcept
    {
        assert(size < length);
        Path p{{}};
        p.length = size;
        std::copy_n(nibbles, size, p.nibbles);
        return p;
    }

    [[nodiscard]] bytes encode(bool extended) const
    {
        bytes bs;
        const auto is_even = length % 2 == 0;
        if (is_even)
            bs.push_back(0x00);
        else
            bs.push_back(0x10 | nibbles[0]);
        for (size_t i = is_even ? 0 : 1; i < length; ++i)
        {
            const auto h = nibbles[i++];
            const auto l = nibbles[i];
            assert(h <= 0x0f);
            assert(l <= 0x0f);
            bs.push_back(uint8_t((h << 4) | l));
        }
        if (!extended)
            bs[0] |= 0x20;
        return bs;
    }
};
}  // namespace

/// The MPT Node.
///
/// The implementation is based on StackTrie from go-ethereum.
class MPTNode
{
    enum class Kind : uint8_t
    {
        leaf,
        ext,
        branch
    };

    static constexpr size_t num_children = 16;

    Kind m_kind = Kind::leaf;
    Path m_path{{}};
    bytes m_value;
    std::unique_ptr<MPTNode> children[num_children];

    MPTNode(Kind kind, const Path& path, bytes&& value = {}) noexcept
      : m_kind{kind}, m_path{path}, m_value{std::move(value)}
    {}

    /// Named constructor for an extended node.
    static MPTNode ext(const Path& path, std::unique_ptr<MPTNode> child) noexcept
    {
        MPTNode node{Kind::ext, path};
        node.children[0] = std::move(child);
        return node;
    }

    /// Finds the position at witch two paths differ.
    static size_t mismatch(const Path& p1, const Path& p2) noexcept
    {
        assert(p1.length <= p2.length);
        return static_cast<size_t>(
            std::mismatch(p1.nibbles, p1.nibbles + p1.length, p2.nibbles).first - p1.nibbles);
    }

public:
    MPTNode() = default;

    /// Named constructor for a leaf node.
    static MPTNode leaf(const Path& path, bytes&& value) noexcept
    {
        return {Kind::leaf, path, std::move(value)};
    }

    void insert(const Path& path, bytes&& value);

    [[nodiscard]] hash256 hash() const;
};

void MPTNode::insert(const Path& path, bytes&& value)  // NOLINT(misc-no-recursion)
{
    switch (m_kind)
    {
    case Kind::branch:
    {
        assert(m_path.length == 0);
        const auto idx = path.nibbles[0];
        auto& child = children[idx];
        if (!child)
            child = std::make_unique<MPTNode>(leaf(path.tail(1), std::move(value)));
        else
            child->insert(path.tail(1), std::move(value));
        break;
    }

    case Kind::ext:
    {
        const auto m = mismatch(m_path, path);

        if (m == m_path.length)
        {
            // Go into child.
            return children[0]->insert(path.tail(m), std::move(value));
        }

        std::unique_ptr<MPTNode> n;
        if (m < m_path.length - 1)
            n = std::make_unique<MPTNode>(ext(m_path.tail(m + 1), std::move(children[0])));
        else
            n = std::move(children[0]);

        MPTNode* branch = nullptr;
        if (m == 0)
        {
            branch = this;
            branch->m_kind = Kind::branch;
        }
        else
        {
            branch = (children[0] = std::make_unique<MPTNode>()).get();
            branch->m_kind = Kind::branch;
        }

        const auto origIdx = m_path.nibbles[m];
        const auto newIdx = path.nibbles[m];

        branch->children[origIdx] = std::move(n);
        branch->children[newIdx] =
            std::make_unique<MPTNode>(leaf(path.tail(m + 1), std::move(value)));
        m_path = m_path.head(m);
        break;
    }

    case Kind::leaf:
    {
        // TODO: Add assert for k == key.
        const auto m = mismatch(m_path, path);

        MPTNode* branch = nullptr;
        if (m == 0)  // Convert into a branch.
        {
            m_kind = Kind::branch;
            branch = this;
        }
        else
        {
            m_kind = Kind::ext;
            branch = (children[0] = std::make_unique<MPTNode>()).get();
            branch->m_kind = Kind::branch;
        }

        const auto orig_pos = m_path.nibbles[m];
        branch->children[orig_pos] =
            std::make_unique<MPTNode>(leaf(m_path.tail(m + 1), std::move(m_value)));

        const auto new_pos = path.nibbles[m];
        assert(orig_pos != new_pos);
        branch->children[new_pos] =
            std::make_unique<MPTNode>(leaf(path.tail(m + 1), std::move(value)));

        m_path = m_path.head(m);
        break;
    }

    default:
        assert(false);
    }
}

hash256 MPTNode::hash() const  // NOLINT(misc-no-recursion)
{
    hash256 r{};
    switch (m_kind)
    {
    case Kind::leaf:
    {
        const auto node = rlp::encode_tuple(m_path.encode(false), m_value);
        r = keccak256(node);
        break;
    }
    case Kind::branch:
    {
        assert(m_path.length == 0);

        // Temporary storage for children hashes.
        // The `bytes` type could be used instead, but this way dynamic allocation is avoided.
        hash256 children_hashes[num_children];

        // Views of children hash bytes. Additional item for hash list
        // terminator (always empty). Does not seem needed for correctness,
        // but this is what the spec says.
        bytes_view children_hash_bytes[num_children + 1];

        for (size_t i = 0; i < num_children; ++i)
        {
            if (children[i])
            {
                children_hashes[i] = children[i]->hash();
                children_hash_bytes[i] = children_hashes[i];
            }
        }

        r = keccak256(rlp::encode(children_hash_bytes));
        break;
    }
    case Kind::ext:
    {
        const auto branch = children[0].get();
        assert(branch != nullptr);
        assert(branch->m_kind == Kind::branch);
        r = keccak256(rlp::encode_tuple(m_path.encode(true), branch->hash()));
        break;
    }
    default:
        assert(false);
    }

    return r;
}


MPT::MPT() noexcept = default;
MPT::~MPT() noexcept = default;

void MPT::insert(bytes_view key, bytes&& value)
{
    if (m_root == nullptr)
        m_root = std::make_unique<MPTNode>(MPTNode::leaf(Path{key}, std::move(value)));
    else
        m_root->insert(Path{key}, std::move(value));
}

[[nodiscard]] hash256 MPT::hash() const
{
    if (m_root == nullptr)
        return emptyMPTHash;
    return m_root->hash();
}

}  // namespace evmone::state
