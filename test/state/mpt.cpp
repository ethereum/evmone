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
/// The MPT node kind.
enum class Kind : uint8_t
{
    leaf,
    ext,
    branch
};

/// The collection of nibbles (4-bit values) representing a path in a MPT.
///
/// TODO(c++26): This is an instance of std::inplace_vector.
class Path
{
    static constexpr size_t max_size = 64;

    size_t m_size = 0;  // TODO: Can be converted to uint8_t.
    uint8_t m_nibbles[max_size]{};

public:
    Path() = default;

    /// Constructs a path from a pair of iterators.
    Path(const uint8_t* first, const uint8_t* last) noexcept
      : m_size(static_cast<size_t>(last - first))
    {
        std::copy(first, last, m_nibbles);
    }

    /// Constructs a path from bytes - each byte will produce 2 nibbles in the path.
    explicit Path(bytes_view key) noexcept : m_size{2 * key.size()}
    {
        assert(m_size <= std::size(m_nibbles));
        size_t i = 0;
        for (const auto b : key)
        {
            m_nibbles[i++] = b >> 4;
            m_nibbles[i++] = b & 0x0f;
        }
    }

    [[nodiscard]] static constexpr size_t capacity() noexcept { return max_size; }
    [[nodiscard]] size_t size() const noexcept { return m_size; }
    [[nodiscard]] bool empty() const noexcept { return m_size == 0; }
    [[nodiscard]] uint8_t operator[](size_t index) const noexcept { return m_nibbles[index]; }
    [[nodiscard]] const uint8_t* begin() const noexcept { return m_nibbles; }
    [[nodiscard]] const uint8_t* end() const noexcept { return m_nibbles + m_size; }

    [[nodiscard]] Path tail(size_t pos) const noexcept
    {
        assert(pos > 0 && pos <= m_size);  // MPT never requests whole path copy (pos == 0).
        return {begin() + pos, end()};
    }

    [[nodiscard]] Path head(size_t size) const noexcept
    {
        assert(size < m_size);  // MPT never requests whole path copy (size == length).
        return {begin(), begin() + size};
    }

    [[nodiscard]] bytes encode(Kind kind) const
    {
        const auto is_even = m_size % 2 == 0;
        bytes bs{static_cast<uint8_t>(
            (is_even ? 0x00 : (0x10 | m_nibbles[0])) | (kind == Kind::leaf ? 0x20 : 0x00))};
        for (size_t i = is_even ? 0 : 1; i < m_size; i += 2)
            bs.push_back(static_cast<uint8_t>((m_nibbles[i] << 4) | m_nibbles[i + 1]));
        return bs;
    }
};
}  // namespace

/// The MPT Node.
///
/// The implementation is based on StackTrie from go-ethereum.
// TODO(clang-tidy-17): bug https://github.com/llvm/llvm-project/issues/50006
// NOLINTNEXTLINE(bugprone-reserved-identifier)
class MPTNode
{
    static constexpr size_t num_children = 16;

    Kind m_kind = Kind::leaf;
    Path m_path;
    bytes m_value;
    std::unique_ptr<MPTNode> m_children[num_children];

    explicit MPTNode(Kind kind, const Path& path = {}, bytes&& value = {}) noexcept
      : m_kind{kind}, m_path{path}, m_value{std::move(value)}
    {}

    /// Creates an extended node.
    static MPTNode ext(const Path& path, std::unique_ptr<MPTNode> child) noexcept
    {
        assert(child->m_kind == Kind::branch);
        MPTNode node{Kind::ext, path};
        node.m_children[0] = std::move(child);
        return node;
    }

    /// Optionally wraps the child node with newly created extended node in case
    /// the provided path is not empty.
    static std::unique_ptr<MPTNode> optional_ext(
        const Path& path, std::unique_ptr<MPTNode> child) noexcept
    {
        return (!path.empty()) ? std::make_unique<MPTNode>(ext(path, std::move(child))) :
                                 std::move(child);
    }

    /// Creates a branch node out of two children and optionally extends it with an extended
    /// node in case the path is not empty.
    static MPTNode ext_branch(const Path& path, size_t idx1, std::unique_ptr<MPTNode> child1,
        size_t idx2, std::unique_ptr<MPTNode> child2) noexcept
    {
        assert(idx1 != idx2);
        assert(idx1 < num_children);
        assert(idx2 < num_children);

        MPTNode br{Kind::branch};
        br.m_children[idx1] = std::move(child1);
        br.m_children[idx2] = std::move(child2);

        return (!path.empty()) ? ext(path, std::make_unique<MPTNode>(std::move(br))) :
                                 std::move(br);
    }

    /// Finds the position at witch two paths differ.
    static size_t mismatch(const Path& p1, const Path& p2) noexcept
    {
        assert(p1.size() <= p2.size());
        return static_cast<size_t>(std::ranges::mismatch(p1, p2).in1 - p1.begin());
    }

public:
    MPTNode() = default;

    /// Creates new leaf node.
    static std::unique_ptr<MPTNode> leaf(const Path& path, bytes&& value) noexcept
    {
        return std::make_unique<MPTNode>(MPTNode{Kind::leaf, path, std::move(value)});
    }

    void insert(const Path& path, bytes&& value);

    [[nodiscard]] bytes encode() const;
};

void MPTNode::insert(const Path& path, bytes&& value)  // NOLINT(misc-no-recursion)
{
    // The insertion is all about branch nodes. In happy case we will find an empty slot
    // in an existing branch node. Otherwise, we need to create new branch node
    // (possibly with an adjusted extended node) and transform existing nodes around it.

    switch (m_kind)
    {
    case Kind::branch:
    {
        assert(m_path.empty());  // Branch has no path.

        auto& child = m_children[path[0]];
        if (!child)
            child = leaf(path.tail(1), std::move(value));
        else
            child->insert(path.tail(1), std::move(value));
        break;
    }

    case Kind::ext:
    {
        assert(!m_path.empty());  // Ext must have non-empty path.

        const auto mismatch_pos = mismatch(m_path, path);

        if (mismatch_pos == m_path.size())  // Paths match: go into the child.
            return m_children[0]->insert(path.tail(mismatch_pos), std::move(value));

        const auto orig_idx = m_path[mismatch_pos];
        const auto new_idx = path[mismatch_pos];

        // The original branch node must be pushed down, possible extended with
        // the adjusted extended node if the path split point is not directly at the branch node.
        // Clang Analyzer bug: https://github.com/llvm/llvm-project/issues/47814
        // NOLINTNEXTLINE(clang-analyzer-cplusplus.NewDeleteLeaks)
        auto orig_branch = optional_ext(m_path.tail(mismatch_pos + 1), std::move(m_children[0]));
        auto new_leaf = leaf(path.tail(mismatch_pos + 1), std::move(value));
        *this = ext_branch(m_path.head(mismatch_pos), orig_idx, std::move(orig_branch), new_idx,
            std::move(new_leaf));
        break;
    }

    case Kind::leaf:
    {
        assert(!m_path.empty());  // Leaf must have non-empty path.

        const auto mismatch_pos = mismatch(m_path, path);
        assert(mismatch_pos != m_path.size());  // Paths must be different.

        const auto orig_idx = m_path[mismatch_pos];
        const auto new_idx = path[mismatch_pos];
        auto orig_leaf = leaf(m_path.tail(mismatch_pos + 1), std::move(m_value));
        auto new_leaf = leaf(path.tail(mismatch_pos + 1), std::move(value));
        *this = ext_branch(m_path.head(mismatch_pos), orig_idx, std::move(orig_leaf), new_idx,
            std::move(new_leaf));
        break;
    }

    default:
        assert(false);
    }
}

/// Encodes a node and optionally hashes the encoded bytes
/// if their length exceeds the specified threshold.
static bytes encode_child(const MPTNode& child) noexcept  // NOLINT(misc-no-recursion)
{
    if (auto e = child.encode(); e.size() < 32)
        return e;  // "short" node
    else
        return rlp::encode(keccak256(e));
}

bytes MPTNode::encode() const  // NOLINT(misc-no-recursion)
{
    bytes encoded;
    switch (m_kind)
    {
    case Kind::leaf:
    {
        encoded = rlp::encode(m_path.encode(m_kind)) + rlp::encode(m_value);
        break;
    }
    case Kind::branch:
    {
        assert(m_path.empty());
        static constexpr uint8_t empty = 0x80;  // encoded empty child

        for (const auto& child : m_children)
        {
            if (child)
                encoded += encode_child(*child);
            else
                encoded += empty;
        }
        encoded += empty;  // end indicator
        break;
    }
    case Kind::ext:
    {
        encoded = rlp::encode(m_path.encode(m_kind)) + encode_child(*m_children[0]);
        break;
    }
    }

    return rlp::internal::wrap_list(encoded);
}


MPT::MPT() noexcept = default;
MPT::~MPT() noexcept = default;

void MPT::insert(bytes_view key, bytes&& value)
{
    if (m_root == nullptr)
        m_root = MPTNode::leaf(Path{key}, std::move(value));
    else
        m_root->insert(Path{key}, std::move(value));
}

[[nodiscard]] hash256 MPT::hash() const
{
    if (m_root == nullptr)
        return emptyMPTHash;
    return keccak256(m_root->encode());
}

}  // namespace evmone::state
