// Standalone PS5 v2 PFS layout port from SharpProspero.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/pfs_layout.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace prosperopkg {
namespace {

constexpr std::size_t block_size = 0x10000;
constexpr std::size_t inode_size = 168;
constexpr std::size_t inode_per_block = block_size / inode_size;
constexpr std::uint16_t mode_dir = 0x414D;
constexpr std::uint16_t mode_file = 0x818D;
constexpr std::uint32_t flag_readonly = 0x10;
constexpr std::uint32_t flag_internal = 0x20000;

struct Node;
struct Dir;

struct Node {
    std::string name;
    std::string full_path;
    std::vector<std::byte> data;
    Dir* parent = nullptr;
    std::uint32_t inode = 0;
    std::uint64_t start_block = 0;
    std::int32_t dirent_offset = -1;
    std::uint32_t blocks = 0;
};

struct Dir {
    std::string name;
    std::string full_path;
    Dir* parent = nullptr;
    std::vector<std::unique_ptr<Dir>> dirs;
    std::vector<std::unique_ptr<Node>> files;
    std::vector<std::byte> dirent_bytes;
    std::uint32_t inode = 0;
    std::int32_t dirent_offset = -1;
    std::uint64_t start_block = 0;
    std::uint32_t blocks = 0;
};

[[nodiscard]] std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) noexcept
{
    return (value + alignment - 1u) / alignment * alignment;
}

void write16(std::span<std::byte> out, std::size_t at, std::uint16_t value)
{
    out[at] = static_cast<std::byte>(value & 0xffu);
    out[at + 1] = static_cast<std::byte>(value >> 8u);
}

void write32(std::span<std::byte> out, std::size_t at, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out[at + i] = static_cast<std::byte>(value >> (i * 8u));
    }
}

void write64(std::span<std::byte> out, std::size_t at, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out[at + i] = static_cast<std::byte>(value >> (i * 8u));
    }
}

[[nodiscard]] std::uint32_t path_hash(std::string_view path) noexcept
{
    std::uint32_t value = 0;
    for (const char ch : path) {
        const auto upper = (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - 'a' + 'A') : ch;
        value = static_cast<std::uint32_t>(static_cast<unsigned char>(upper)) + 31u * value;
    }
    return value;
}

[[nodiscard]] std::size_t dirent_size(std::string_view name) noexcept
{
    return (name.size() + 17u + 7u) & ~std::size_t{7u};
}

void append_dirent(std::vector<std::byte>& out, std::uint32_t inode, std::uint32_t type, std::string_view name)
{
    const auto offset = out.size();
    const auto size = dirent_size(name);
    out.resize(offset + size);
    write32(out, offset, inode);
    write32(out, offset + 4, type);
    write32(out, offset + 8, static_cast<std::uint32_t>(name.size()));
    write32(out, offset + 12, static_cast<std::uint32_t>(size));
    for (std::size_t i = 0; i < name.size(); ++i) {
        out[offset + 16 + i] = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

Dir* get_dir(Dir& root, std::map<std::string, Dir*>& lookup, const std::string& path)
{
    if (const auto it = lookup.find(path); it != lookup.end()) {
        return it->second;
    }
    const auto slash = path.find_last_of('/');
    const auto parent_path = slash == std::string::npos ? std::string{} : path.substr(0, slash);
    const auto name = slash == std::string::npos ? path : path.substr(slash + 1);
    auto* parent = get_dir(root, lookup, parent_path);
    auto child = std::make_unique<Dir>();
    child->name = name;
    child->full_path = path;
    child->parent = parent;
    auto* result = child.get();
    parent->dirs.push_back(std::move(child));
    lookup.emplace(path, result);
    return result;
}

[[nodiscard]] std::unique_ptr<Dir> make_tree(std::vector<InnerPfsFile> files)
{
    auto root = std::make_unique<Dir>();
    std::map<std::string, Dir*> lookup{{{}, root.get()}};
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) { return a.path < b.path; });
    for (auto& file : files) {
        while (!file.path.empty() && file.path.front() == '/') {
            file.path.erase(file.path.begin());
        }
        const auto slash = file.path.find_last_of('/');
        const auto parent_path = slash == std::string::npos ? std::string{} : file.path.substr(0, slash);
        const auto name = slash == std::string::npos ? file.path : file.path.substr(slash + 1);
        if (name.empty()) {
            throw std::invalid_argument("PFS input contains an empty file name");
        }
        auto node = std::make_unique<Node>();
        node->name = name;
        node->full_path = "/" + file.path;
        node->data = std::move(file.data);
        node->parent = get_dir(*root, lookup, parent_path);
        node->parent->files.push_back(std::move(node));
    }
    return root;
}

void sort_tree(Dir& dir)
{
    std::sort(dir.dirs.begin(), dir.dirs.end(), [](const auto& a, const auto& b) { return a->name < b->name; });
    std::sort(dir.files.begin(), dir.files.end(), [](const auto& a, const auto& b) { return a->name < b->name; });
    for (auto& child : dir.dirs) {
        sort_tree(*child);
    }
}

void collect_dirs(const Dir& dir, std::vector<Dir*>& output)
{
    for (const auto& child : dir.dirs) {
        output.push_back(child.get());
        collect_dirs(*child, output);
    }
}

void collect_files(const Dir& dir, std::vector<Node*>& output)
{
    for (const auto& file : dir.files) {
        output.push_back(file.get());
    }
    for (const auto& child : dir.dirs) {
        collect_files(*child, output);
    }
}

void build_dirents(Dir& dir)
{
    dir.dirent_bytes.clear();
    append_dirent(dir.dirent_bytes, dir.inode, 4, ".");
    append_dirent(dir.dirent_bytes, dir.parent == nullptr ? dir.inode : dir.parent->inode, 5, "..");
    for (const auto& child : dir.dirs) {
        const auto offset = dir.dirent_bytes.size();
        append_dirent(dir.dirent_bytes, child->inode, 3, child->name);
        child->dirent_offset = static_cast<std::int32_t>(offset);
    }
    for (const auto& file : dir.files) {
        const auto offset = dir.dirent_bytes.size();
        append_dirent(dir.dirent_bytes, file->inode, 2, file->name);
        file->dirent_offset = static_cast<std::int32_t>(offset);
    }
    for (auto& child : dir.dirs) {
        build_dirents(*child);
    }
}

struct InodeInfo {
    std::uint16_t mode = 0;
    std::uint16_t nlink = 1;
    std::uint32_t flags = flag_readonly;
    std::int64_t size = 0;
    std::uint32_t blocks = 0;
    std::uint64_t start_block = 0;
    std::array<std::int32_t, 12> direct{};
    std::array<std::int32_t, 5> indirect{};
};

void write_inode(std::span<std::byte> out, std::size_t at, const InodeInfo& inode,
    std::int64_t timestamp, std::uint32_t timestamp_nanoseconds)
{
    auto dst = out.subspan(at, inode_size);
    std::fill(dst.begin(), dst.end(), std::byte{0});
    write16(dst, 0, inode.mode);
    write16(dst, 2, inode.nlink);
    write32(dst, 4, inode.flags);
    write64(dst, 8, static_cast<std::uint64_t>(inode.size));
    write64(dst, 16, static_cast<std::uint64_t>(inode.size));
    for (unsigned i = 0; i < 4; ++i) {
        write64(dst, 24 + i * 8, static_cast<std::uint64_t>(timestamp));
        write32(dst, 56 + i * 4, timestamp_nanoseconds);
    }
    // D32 inode records store nanoseconds, uid/gid and two reserved words
    // before the block count and 12 direct/5 indirect block numbers.
    write32(dst, 96, inode.blocks);
    for (unsigned i = 0; i < inode.direct.size(); ++i) {
        write32(dst, 100 + i * 4, static_cast<std::uint32_t>(inode.direct[i]));
    }
    for (unsigned i = 0; i < inode.indirect.size(); ++i) {
        write32(dst, 148 + i * 4, static_cast<std::uint32_t>(inode.indirect[i]));
    }
}

void write_inode_block_signature(std::span<std::byte> out, std::size_t at,
    std::uint64_t block_count, std::uint64_t first_block, std::int64_t timestamp)
{
    auto sig = out.subspan(at, 784);
    std::fill(sig.begin(), sig.end(), std::byte{0});
    write16(sig, 0, 0);
    write16(sig, 2, 1);
    write32(sig, 4, flag_readonly);
    write64(sig, 8, block_count * block_size);
    write64(sig, 16, block_count * block_size);
    for (unsigned i = 0; i < 4; ++i) {
        write64(sig, 24 + i * 8, static_cast<std::uint64_t>(timestamp));
    }
    write64(sig, 96, block_count);
    // ProsperoBlockSig64 is a 32-byte HMAC followed by an int64 block.
    write64(sig, 100, first_block);
    for (unsigned i = 1; i < 12; ++i) {
        write64(sig, 100 + i * 40, std::numeric_limits<std::uint64_t>::max());
    }
}

} // namespace

InnerPfsLayout build_standalone_pfs_layout(
    std::vector<InnerPfsFile> files,
    std::int64_t timestamp_seconds,
    std::uint32_t timestamp_nanoseconds)
{
    if (files.empty()) {
        throw std::invalid_argument("at least one PFS file is required");
    }
    auto root = make_tree(std::move(files));
    sort_tree(*root);
    std::vector<Dir*> dirs;
    collect_dirs(*root, dirs);
    std::vector<Node*> file_nodes;
    collect_files(*root, file_nodes);

    // SharpProspero reserves inode 0 for the super-root and inode 1 for the
    // flat-path table. The user root is inode 2, followed by directories/files.
    std::vector<InodeInfo> inodes(3 + dirs.size() + file_nodes.size());
    for (auto& inode : inodes) {
        inode.direct.fill(-1);
        inode.indirect.fill(-1);
    }
    inodes[0] = InodeInfo{mode_dir, 1, flag_readonly | flag_internal, block_size, 1, 0};
    inodes[1] = InodeInfo{mode_file, 1, flag_readonly | flag_internal, 0, 0, 0};
    root->inode = 2;
    std::uint32_t next_inode = 3;
    for (auto* dir : dirs) {
        dir->inode = next_inode++;
    }
    for (auto* file : file_nodes) {
        file->inode = next_inode++;
    }

    build_dirents(*root);
    for (auto* dir : dirs) {
        dir->blocks = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, align_up(dir->dirent_bytes.size(), block_size) / block_size));
    }
    root->blocks = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, align_up(root->dirent_bytes.size(), block_size) / block_size));

    std::vector<std::pair<std::uint32_t, std::uint32_t>> flat_entries;
    for (auto* dir : dirs) {
        const auto hash = path_hash(dir->full_path);
        const auto value = dir->inode | 0x20000000u;
        flat_entries.emplace_back(hash, value);
    }
    for (auto* file : file_nodes) {
        flat_entries.emplace_back(path_hash(file->full_path), file->inode);
    }
    std::sort(flat_entries.begin(), flat_entries.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });
    for (std::size_t i = 1; i < flat_entries.size(); ++i) {
        if (flat_entries[i - 1].first == flat_entries[i].first) {
            throw std::runtime_error("standalone PFS flat-path hash collision requires a collision resolver");
        }
    }
    std::vector<std::byte> flat;
    flat.reserve(flat_entries.size() * 8);
    for (const auto& entry : flat_entries) {
        const auto at = flat.size();
        flat.resize(at + 8);
        write32(flat, at, entry.first);
        write32(flat, at + 4, entry.second);
    }
    inodes[1].size = static_cast<std::int64_t>(flat.size());
    inodes[1].blocks = static_cast<std::uint32_t>((flat.size() + block_size - 1u) / block_size);

    const auto inode_blocks = (inodes.size() + inode_per_block - 1u) / inode_per_block;
    std::uint64_t next_block = 1 + inode_blocks;
    inodes[0].start_block = next_block++;
    inodes[0].blocks = 1;
    inodes[0].direct[0] = static_cast<std::int32_t>(inodes[0].start_block);
    inodes[1].start_block = next_block;
    inodes[1].blocks = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, (flat.size() + block_size - 1u) / block_size));
    inodes[1].direct[0] = static_cast<std::int32_t>(inodes[1].start_block);
    next_block += inodes[1].blocks;
    // Block after the flat-path table is deliberately left empty when there
    // is no collision resolver, matching ProsperoPfsBuilder.
    ++next_block;

    auto assign_node = [&](InodeInfo& inode, std::uint64_t size, std::uint64_t& cursor) {
        inode.size = static_cast<std::int64_t>(size);
        inode.blocks = static_cast<std::uint32_t>((size + block_size - 1u) / block_size);
        if (inode.blocks > 12) {
            throw std::runtime_error("standalone PFS file exceeds the direct-block limit");
        }
        inode.start_block = cursor;
        for (std::uint32_t i = 0; i < inode.blocks; ++i) {
            inode.direct[i] = static_cast<std::int32_t>(cursor + i);
        }
        cursor += inode.blocks;
    };
    inodes[2].mode = mode_dir;
    inodes[2].nlink = static_cast<std::uint16_t>(3u + root->dirs.size());
    assign_node(inodes[2], align_up(root->dirent_bytes.size(), block_size), next_block);
    for (auto* dir : dirs) {
        inodes[dir->inode].mode = mode_dir;
        inodes[dir->inode].nlink = static_cast<std::uint16_t>(2u + dir->dirs.size());
        assign_node(inodes[dir->inode], align_up(dir->dirent_bytes.size(), block_size), next_block);
    }
    for (auto* file : file_nodes) {
        inodes[file->inode].mode = mode_file;
        assign_node(inodes[file->inode], file->data.size(), next_block);
    }

    const auto image_size = next_block * block_size;
    std::vector<std::byte> image(static_cast<std::size_t>(image_size));
    auto header = std::span<std::byte>(image).first(block_size);
    write64(header, 0, 2);
    write64(header, 8, 20130315);
    header[0x1A] = std::byte{1}; // read-only
    write16(header, 0x1C, 8); // UnknownFlagAlwaysSet
    write32(header, 0x20, block_size);
    write32(header, 0x24, 0); // nbackup
    write64(header, 0x28, 1); // nblock
    write64(header, 0x30, inodes.size());
    write64(header, 0x38, next_block); // ndblock
    write64(header, 0x40, inode_blocks);
    write_inode_block_signature(header, 0x50, inode_blocks, 1, timestamp_seconds);
    write32(header, 0x36C, 1);

    for (std::size_t i = 0; i < inodes.size(); ++i) {
        write_inode(image, block_size + i * inode_size, inodes[i], timestamp_seconds, timestamp_nanoseconds);
    }
    const auto super_root_offset = static_cast<std::size_t>(inodes[0].start_block * block_size);
    auto super_root = std::span<std::byte>(image).subspan(super_root_offset, block_size);
    std::vector<std::byte> super_dirents;
    append_dirent(super_dirents, 1, 2, "flat_path_table");
    append_dirent(super_dirents, 2, 3, "uroot");
    std::copy(super_dirents.begin(), super_dirents.end(), super_root.begin());
    std::copy(flat.begin(), flat.end(), image.begin() + static_cast<std::ptrdiff_t>(inodes[1].start_block * block_size));

    auto write_node_data = [&](const auto& node, const InodeInfo& inode, std::span<const std::byte> data) {
        if (data.empty()) {
            return;
        }
        std::copy(data.begin(), data.end(), image.begin() + static_cast<std::ptrdiff_t>(inode.start_block * block_size));
    };
    write_node_data(*root, inodes[2], root->dirent_bytes);
    for (auto* dir : dirs) {
        write_node_data(*dir, inodes[dir->inode], dir->dirent_bytes);
    }
    for (auto* file : file_nodes) {
        write_node_data(*file, inodes[file->inode], file->data);
    }

    return InnerPfsLayout{std::move(image), static_cast<std::int64_t>(next_block), 0, inodes.size(), file_nodes.size()};
}

} // namespace prosperopkg
