// LibProsperoPkg PS5 inner PFS layout port.
// C++ port/rewrite Copyright (C) 2026 seregonwar and SDK contributors.
// Original C# LibProsperoPkg by SvenGDK.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/pfs_layout.hpp>
#include <prosperopkg/pfsc.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace prosperopkg {
namespace {

constexpr std::size_t block_size = 0x10000;
constexpr std::size_t inode_size = 168;

struct Dirent {
    std::uint32_t inode = 0;
    std::uint32_t type = 0;
    std::string name;

    [[nodiscard]] std::size_t size() const noexcept
    {
        return (name.size() + 17u + 7u) & ~std::size_t{7u};
    }
};

struct Directory;

struct FileNode {
    std::string name;
    std::string full_path;
    std::vector<std::byte> data;
    std::vector<std::byte> on_disk_data;
    std::vector<InnerPfsBlockPlacement> compressed_blocks;
    Directory* parent = nullptr;
    std::uint32_t inode = 0;
    std::uint32_t afid = 0;
    std::uint64_t logical_offset = 0;
    std::int32_t dirent_offset = -1;
    std::uint64_t on_disk_offset = 0;
    bool sce_sys = false;
    bool whole_block_raw = false;
    bool store_raw = true;
};

struct Directory {
    std::string name;
    std::string full_path;
    Directory* parent = nullptr;
    std::vector<std::unique_ptr<Directory>> directories;
    std::vector<std::unique_ptr<FileNode>> files;
    std::vector<Dirent> dirents;
    std::uint32_t inode = 0;
    std::int32_t dirent_offset = -1;
};

struct MetaNode {
    std::string name;
    std::uint32_t inode = 0;
    bool directory = false;
    std::uint32_t afid = 0;
    std::uint64_t logical_offset = 0;
    std::int64_t size = 0;
    std::uint16_t mode = 0;
    std::uint16_t nlink = 1;
    std::uint32_t flags = 0;
    std::int32_t parent_inode = -1;
    std::int32_t dirent_offset = -1;
};

struct FlatEntry {
    std::uint64_t hash = 0;
    std::uint64_t packed = 0;
};

[[nodiscard]] std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) noexcept
{
    return (value + alignment - 1u) / alignment * alignment;
}

[[nodiscard]] std::uint32_t read_le32(std::span<const std::byte> input, std::size_t offset) noexcept
{
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(input[offset + index]) << (index * 8u);
    }
    return value;
}

[[nodiscard]] std::uint64_t read_le64(std::span<const std::byte> input, std::size_t offset) noexcept
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8u);
    }
    return value;
}

struct CompressedPayload {
    std::vector<std::byte> data;
    std::vector<InnerPfsBlockPlacement> blocks;
};

[[nodiscard]] CompressedPayload compress_payload(std::span<const std::byte> raw)
{
    const auto container = pack_pfsc_pfs_v3_compressed(raw, 7, 0x40000);
    constexpr std::size_t directory_offset = 0x48;
    constexpr std::size_t directory_entry_size = 0x10;
    constexpr std::uint64_t offset_mask = (1ull << 44u) - 1u;
    const auto boundary_offset = read_le32(container, directory_offset + 2u * directory_entry_size + 2u);
    const auto boundary_size = read_le32(container, directory_offset + 2u * directory_entry_size + 10u);
    const auto data_offset = read_le32(container, directory_offset + 6u * directory_entry_size + 2u);
    if (boundary_size < 2u * directory_entry_size || boundary_size % directory_entry_size != 0) {
        throw std::runtime_error("Kraken PFSC boundary table is malformed");
    }
    const auto block_count = boundary_size / directory_entry_size - 1u;
    CompressedPayload result;
    for (std::uint32_t index = 0; index < block_count; ++index) {
        const auto entry = boundary_offset + index * directory_entry_size;
        const auto next_entry = entry + directory_entry_size;
        const auto first = read_le64(container, entry);
        const auto second = read_le64(container, entry + 8u);
        const auto next_first = read_le64(container, next_entry);
        const auto next_second = read_le64(container, next_entry + 8u);
        const auto compressed_start = first & offset_mask;
        const auto compressed_end = next_first & offset_mask;
        const auto logical_start = second & offset_mask;
        const auto logical_end = next_second & offset_mask;
        const auto flags = static_cast<std::uint16_t>(first >> 48u);
        if (compressed_end < compressed_start || data_offset + compressed_end > container.size()) {
            throw std::runtime_error("Kraken PFSC data section is malformed");
        }
        const bool compressed = (flags & 0x06u) == 0x06u;
        const bool multi_chunk = compressed && (flags & 0x20u) != 0;
        result.blocks.push_back(InnerPfsBlockPlacement{
            compressed_start,
            logical_start,
            compressed_end - compressed_start,
            logical_end - logical_start,
            compressed,
            multi_chunk,
            multi_chunk ? ((second >> 44u) & 0x1FFFFu) + 1u : compressed_end - compressed_start});
    }
    const auto data_size = result.blocks.empty()
        ? 0u
        : result.blocks.back().on_disk_offset + result.blocks.back().on_disk_size;
    result.data.assign(
        container.begin() + static_cast<std::ptrdiff_t>(data_offset),
        container.begin() + static_cast<std::ptrdiff_t>(data_offset + data_size));
    return result;
}

void write_le16(std::span<std::byte> output, std::size_t offset, std::uint16_t value)
{
    output[offset] = static_cast<std::byte>(value & 0xFFu);
    output[offset + 1] = static_cast<std::byte>((value >> 8u) & 0xFFu);
}

void write_le32(std::span<std::byte> output, std::size_t offset, std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::byte>((value >> (index * 8u)) & 0xFFu);
    }
}

void write_le64(std::span<std::byte> output, std::size_t offset, std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] = static_cast<std::byte>((value >> (index * 8u)) & 0xFFu);
    }
}

void append_le32(std::vector<std::byte>& output, std::uint32_t value)
{
    const auto offset = output.size();
    output.resize(offset + 4);
    write_le32(output, offset, value);
}

void append_le64(std::vector<std::byte>& output, std::uint64_t value)
{
    const auto offset = output.size();
    output.resize(offset + 8);
    write_le64(output, offset, value);
}

void append_dirent(std::vector<std::byte>& output, const Dirent& dirent)
{
    const auto start = output.size();
    output.resize(start + dirent.size());
    write_le32(output, start, dirent.inode);
    write_le32(output, start + 4, dirent.type);
    write_le32(output, start + 8, static_cast<std::uint32_t>(dirent.name.size()));
    write_le32(output, start + 12, static_cast<std::uint32_t>(dirent.size()));
    for (std::size_t index = 0; index < dirent.name.size(); ++index) {
        output[start + 16 + index] = static_cast<std::byte>(dirent.name[index]);
    }
}

[[nodiscard]] std::uint64_t rotate_left(std::uint64_t value, unsigned bits) noexcept
{
    return (value << bits) | (value >> (64u - bits));
}

[[nodiscard]] std::uint64_t rotate_right(std::uint64_t value, unsigned bits) noexcept
{
    return (value >> bits) | (value << (64u - bits));
}

[[nodiscard]] std::uint64_t read_le64_partial(std::span<const std::byte> input) noexcept
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < input.size(); ++index) {
        value |= static_cast<std::uint64_t>(input[index]) << (index * 8u);
    }
    return value;
}

[[nodiscard]] std::uint64_t hash_path(std::string path)
{
    if (!path.empty() && path.front() == '/') {
        path.erase(path.begin());
    }
    std::vector<std::byte> bytes;
    bytes.reserve(path.size());
    // SharpProspero uppercases the managed string invariantly and then uses
    // ASCII encoding for the FLT hash.  Preserve that deterministic behavior
    // for UTF-8 paths instead of applying the host locale to signed bytes.
    for (std::size_t index = 0; index < path.size();) {
        const auto ch = static_cast<unsigned char>(path[index]);
        if (ch < 0x80u) {
            bytes.push_back(static_cast<std::byte>(ch >= 'a' && ch <= 'z' ? ch - 'a' + 'A' : ch));
            ++index;
            continue;
        }
        std::size_t width = 1;
        if ((ch & 0xE0u) == 0xC0u) width = 2;
        else if ((ch & 0xF0u) == 0xE0u) width = 3;
        else if ((ch & 0xF8u) == 0xF0u) width = 4;
        if (index + width > path.size()) width = 1;
        bytes.push_back(std::byte{'?'});
        index += width;
    }

    constexpr std::uint64_t seed = 10577419142525243217ull;
    constexpr std::uint64_t round_constant = 0x8000000080008081ull;
    std::uint64_t a = seed;
    std::uint64_t b = rotate_left(seed, 11);
    std::uint64_t c = rotate_left(seed, 23);
    std::uint64_t tail = 0;
    if (!bytes.empty()) {
        const std::size_t rounds = (bytes.size() - 1u) >> 3u;
        std::size_t offset = 0;
        for (std::size_t round = 0; round < rounds; ++round) {
            a ^= read_le64_partial(std::span<const std::byte>(bytes).subspan(offset, 8));
            const auto x = rotate_right(rotate_left(c ^ b, 5) ^ a, 11);
            const auto y = rotate_left(rotate_left(c ^ a, 17) ^ b, 11);
            const auto z = rotate_right(rotate_left(b ^ a, 1) ^ c, 5);
            a = (~y & z) ^ x ^ round_constant;
            b = (~z & x) ^ y;
            c = (~x & y) ^ z;
            offset += 8;
        }
        tail = read_le64_partial(std::span<const std::byte>(bytes).subspan(offset));
    }
    const auto mixed = tail ^ a ^ 0x09BBB761A41BC44Dull;
    const auto x = rotate_left(c ^ b, 5) ^ mixed;
    const auto y = rotate_left(c ^ mixed, 17) ^ b;
    const auto z = rotate_left(b ^ mixed, 1) ^ c;
    return (~rotate_left(y, 11) & rotate_right(z, 5)) ^ rotate_right(x, 11) ^ round_constant;
}

[[nodiscard]] std::uint64_t pack_inode_entry(
    std::uint32_t inode,
    bool directory,
    bool subtree,
    std::uint32_t afid) noexcept
{
    std::uint64_t value = inode & 0xFFFFFFu;
    if (directory) {
        value |= 0x40000000ull;
    }
    if (subtree) {
        value |= 0x80000000ull;
    }
    return value | (static_cast<std::uint64_t>(directory ? 0xFFFFFFu : afid) << 40u);
}

[[nodiscard]] std::uint64_t pack_apr_entry(std::int64_t size, std::uint32_t afid) noexcept
{
    return (static_cast<std::uint64_t>(size) & 0xFFFFFFFFFFull) |
           (static_cast<std::uint64_t>(afid) << 40u);
}

[[nodiscard]] std::vector<std::byte> build_flat_table(std::vector<FlatEntry> entries)
{
    std::sort(entries.begin(), entries.end(), [](const FlatEntry& left, const FlatEntry& right) {
        return left.hash < right.hash;
    });
    std::vector<std::byte> output(64);
    write_le32(output, 0, 1);
    output[4] = std::byte{16};
    write_le32(output, 8, 64);
    output[32] = std::byte{0x7F};
    output[33] = std::byte{'F'};
    output[34] = std::byte{'L'};
    output[35] = std::byte{'T'};
    write_le32(output, 44, static_cast<std::uint32_t>(entries.size()));
    constexpr std::array<std::byte, 16> header_seed{
        std::byte{81}, std::byte{79}, std::byte{162}, std::byte{38},
        std::byte{171}, std::byte{138}, std::byte{202}, std::byte{146},
        std::byte{77}, std::byte{196}, std::byte{27}, std::byte{164},
        std::byte{97}, std::byte{183}, std::byte{187}, std::byte{9}};
    std::copy(header_seed.begin(), header_seed.end(), output.begin() + 48);
    for (const auto& entry : entries) {
        append_le64(output, entry.hash);
        append_le64(output, entry.packed);
    }
    return output;
}

[[nodiscard]] bool starts_with(std::string_view value, std::string_view prefix) noexcept
{
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

[[nodiscard]] bool executable_module(std::span<const std::byte> data) noexcept
{
    if (data.size() < 4) {
        return false;
    }
    const auto magic = static_cast<std::uint32_t>(data[0]) |
        (static_cast<std::uint32_t>(data[1]) << 8u) |
        (static_cast<std::uint32_t>(data[2]) << 16u) |
        (static_cast<std::uint32_t>(data[3]) << 24u);
    return magic == 0x1D3D154Fu || magic == 0x464C457Fu || magic == 0xEEF51454u;
}

Directory* get_directory(Directory& root, std::map<std::string, Directory*>& lookup, const std::string& path)
{
    if (const auto found = lookup.find(path); found != lookup.end()) {
        return found->second;
    }
    const auto slash = path.find_last_of('/');
    const std::string parent_path = slash == std::string::npos ? std::string{} : path.substr(0, slash);
    const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    auto* parent = get_directory(root, lookup, parent_path);
    auto directory = std::make_unique<Directory>();
    directory->name = name;
    directory->full_path = path;
    directory->parent = parent;
    auto* result = directory.get();
    parent->directories.push_back(std::move(directory));
    lookup[path] = result;
    return result;
}

[[nodiscard]] std::unique_ptr<Directory> build_tree(std::vector<InnerPfsFile> files)
{
    auto root = std::make_unique<Directory>();
    root->name = "uroot";
    std::map<std::string, Directory*> lookup{{"", root.get()}};
    std::sort(files.begin(), files.end(), [](const InnerPfsFile& left, const InnerPfsFile& right) {
        return left.path < right.path;
    });
    for (auto& file : files) {
        while (!file.path.empty() && file.path.front() == '/') {
            file.path.erase(file.path.begin());
        }
        const auto slash = file.path.find_last_of('/');
        const std::string parent_path = slash == std::string::npos ? std::string{} : file.path.substr(0, slash);
        const std::string name = slash == std::string::npos ? file.path : file.path.substr(slash + 1);
        if (name.empty()) {
            throw std::invalid_argument("PFS input contains an empty file name");
        }
        auto node = std::make_unique<FileNode>();
        node->name = name;
        node->full_path = "/" + file.path;
        node->data = std::move(file.data);
        node->parent = get_directory(*root, lookup, parent_path);
        node->parent->files.push_back(std::move(node));
    }
    return root;
}

void collect_preorder(Directory& directory, std::vector<Directory*>& output)
{
    output.push_back(&directory);
    std::sort(directory.directories.begin(), directory.directories.end(), [](const auto& left, const auto& right) {
        return left->name < right->name;
    });
    for (auto& child : directory.directories) {
        collect_preorder(*child, output);
    }
}

void collect_postorder(Directory& directory, std::vector<Directory*>& output)
{
    std::sort(directory.directories.begin(), directory.directories.end(), [](const auto& left, const auto& right) {
        return left->name < right->name;
    });
    for (auto& child : directory.directories) {
        collect_postorder(*child, output);
    }
    output.push_back(&directory);
}

void collect_files_preorder(Directory& directory, std::vector<FileNode*>& output)
{
    std::sort(directory.files.begin(), directory.files.end(), [](const auto& left, const auto& right) {
        return left->name < right->name;
    });
    for (auto& file : directory.files) {
        output.push_back(file.get());
    }
    for (auto& child : directory.directories) {
        collect_files_preorder(*child, output);
    }
}

[[nodiscard]] bool under(const Directory* directory, const Directory* ancestor) noexcept
{
    for (auto current = directory; current != nullptr; current = current->parent) {
        if (current == ancestor) {
            return true;
        }
    }
    return false;
}

void build_dirents(Directory& directory)
{
    directory.dirents.clear();
    directory.dirents.push_back(Dirent{directory.inode, 4, "."});
    directory.dirents.push_back(Dirent{directory.parent == nullptr ? directory.inode : directory.parent->inode, 5, ".."});
    for (const auto& child : directory.directories) {
        directory.dirents.push_back(Dirent{child->inode, 3, child->name});
    }
    for (const auto& file : directory.files) {
        directory.dirents.push_back(Dirent{file->inode, 2, file->name});
    }
    std::size_t offset = 0;
    for (const auto& dirent : directory.dirents) {
        for (auto& child : directory.directories) {
            if (child->name == dirent.name) {
                child->dirent_offset = static_cast<std::int32_t>(offset);
            }
        }
        for (auto& file : directory.files) {
            if (file->name == dirent.name) {
                file->dirent_offset = static_cast<std::int32_t>(offset);
            }
        }
        offset += dirent.size();
    }
    for (auto& child : directory.directories) {
        build_dirents(*child);
    }
}

[[nodiscard]] MetaNode meta_file(std::uint32_t inode, std::uint64_t offset, std::uint32_t flags, std::string name)
{
    MetaNode node;
    node.name = std::move(name);
    node.inode = inode;
    node.mode = 33133;
    node.flags = flags;
    node.logical_offset = offset;
    return node;
}

[[nodiscard]] std::vector<std::byte> serialize_dirents(const std::vector<Dirent>& dirents)
{
    std::vector<std::byte> output;
    for (const auto& dirent : dirents) {
        append_dirent(output, dirent);
    }
    return output;
}

void write_inode(
    std::span<std::byte> output,
    std::size_t offset,
    const MetaNode& node,
    std::int64_t time_seconds,
    std::uint32_t time_nanoseconds)
{
    auto inode = output.subspan(offset, inode_size);
    std::fill(inode.begin(), inode.end(), std::byte{0});
    write_le16(inode, 0, node.mode);
    write_le16(inode, 2, node.nlink);
    write_le32(inode, 4, node.flags);
    write_le64(inode, 8, static_cast<std::uint64_t>(node.size));
    write_le64(inode, 16, static_cast<std::uint64_t>(node.size));
    for (std::size_t index = 0; index < 4; ++index) {
        write_le64(inode, 24 + index * 8, static_cast<std::uint64_t>(time_seconds));
        write_le32(inode, 56 + index * 4, time_nanoseconds);
    }
    write_le64(inode, 96, node.logical_offset);
    write_le32(inode, 100, 0);
    const auto value = node.parent_inode < 0 ? -1 : (node.directory ? -1 : static_cast<std::int32_t>(node.afid));
    write_le32(inode, 104, static_cast<std::uint32_t>(value));
    write_le32(inode, 108, static_cast<std::uint32_t>(node.parent_inode));
    write_le32(inode, 112, static_cast<std::uint32_t>(node.dirent_offset));
}

[[nodiscard]] std::vector<std::byte> build_metadata(
    const std::vector<MetaNode>& nodes,
    std::int64_t logical_blocks,
    const std::vector<std::vector<std::byte>>& blocks,
    std::int64_t time_seconds,
    std::uint32_t time_nanoseconds)
{
    std::vector<std::byte> output((2u + blocks.size()) * block_size);
    write_le64(output, 0, 2);
    write_le64(output, 8, 20130315);
    output[26] = std::byte{1};
    write_le16(output, 28, 24);
    write_le32(output, 32, static_cast<std::uint32_t>(block_size));
    write_le64(output, 40, 1);
    write_le64(output, 48, nodes.size());
    write_le64(output, 56, static_cast<std::uint64_t>(logical_blocks));
    write_le64(output, 64, 1);
    write_le32(output, 80, static_cast<std::uint32_t>(block_size));
    write_le32(output, 84, 16);
    write_le32(output, 88, static_cast<std::uint32_t>(block_size));
    write_le32(output, 96, static_cast<std::uint32_t>(block_size));
    for (std::size_t index = 0; index < 4; ++index) {
        write_le64(output, 104 + index * 8, static_cast<std::uint64_t>(time_seconds));
        write_le32(output, 136 + index * 4, time_nanoseconds);
    }
    write_le64(output, 176, 1);
    write_le64(output, 216, 137);
    output[872] = std::byte{1};
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        write_inode(output, block_size + index * inode_size, nodes[index], time_seconds, time_nanoseconds);
    }
    for (std::size_t index = 0; index < blocks.size(); ++index) {
        if (blocks[index].size() > block_size) {
            throw std::runtime_error("PFS metadata block exceeds 64 KiB");
        }
        std::copy(blocks[index].begin(), blocks[index].end(), output.begin() + (2u + index) * block_size);
    }
    return output;
}

[[nodiscard]] std::vector<std::byte> block_info_table(std::uint64_t app_size)
{
    const auto adjusted = static_cast<std::uint32_t>((4u * app_size) & 0xFFFFFu);
    const auto raw = (2570044u - adjusted) & 0xFFFFFFu;
    const auto value = ((raw & 0xFFu) << 16u) | (raw & 0xFF00u) | ((raw >> 16u) & 0xFFu);
    std::vector<std::byte> output(32);
    const std::array<std::uint32_t, 4> values{16580391u, 16580391u, 16580391u, value};
    for (std::size_t index = 0; index < values.size(); ++index) {
        write_le32(output, index * 8, values[index]);
        write_le32(output, index * 8 + 4, 4194307u);
    }
    return output;
}

} // namespace

InnerPfsLayout build_inner_pfs_layout(
    std::vector<InnerPfsFile> files,
    std::int64_t timestamp_seconds,
    std::uint32_t timestamp_nanoseconds)
{
    if (files.empty()) {
        throw std::invalid_argument("at least one inner PFS file is required");
    }
    auto root = build_tree(std::move(files));
    std::vector<Directory*> preorder;
    std::vector<Directory*> postorder;
    collect_preorder(*root, preorder);
    collect_postorder(*root, postorder);

    std::uint32_t next_inode = 0;
    const auto super_root_inode = next_inode++;
    const auto inode_flt_inode = next_inode++;
    const auto apr_flt_inode = next_inode++;
    const auto afid_table_inode = next_inode++;
    for (auto* directory : preorder) {
        directory->inode = next_inode++;
    }

    std::vector<FileNode*> inode_files;
    for (auto* directory : postorder) {
        std::sort(directory->files.begin(), directory->files.end(), [](const auto& left, const auto& right) {
            return left->name < right->name;
        });
        for (auto& file : directory->files) {
            file->inode = next_inode++;
            inode_files.push_back(file.get());
        }
    }

    Directory* sce_sys = nullptr;
    for (const auto& directory : root->directories) {
        if (directory->name == "sce_sys") {
            sce_sys = directory.get();
            break;
        }
    }
    std::vector<FileNode*> afid_files;
    if (sce_sys != nullptr) {
        collect_files_preorder(*sce_sys, afid_files);
    }
    for (auto* directory : preorder) {
        if (directory == sce_sys || under(directory, sce_sys)) {
            continue;
        }
        for (auto& file : directory->files) {
            afid_files.push_back(file.get());
        }
    }

    std::uint64_t logical_cursor = 0;
    for (std::size_t index = 0; index < afid_files.size(); ++index) {
        auto& file = *afid_files[index];
        file.afid = static_cast<std::uint32_t>(index);
        file.logical_offset = logical_cursor;
        logical_cursor += file.data.size();
        file.sce_sys = starts_with(file.full_path, "/sce_sys/");
        file.whole_block_raw = file.full_path == "/sce_sys/keystone";
        if (file.whole_block_raw || executable_module(file.data)) {
            file.on_disk_data = file.data;
        } else {
            auto compressed = compress_payload(file.data);
            const auto threshold = (file.data.size() * 15u) >> 4u;
            if (compressed.data.size() <= threshold) {
                file.store_raw = false;
                file.on_disk_data = std::move(compressed.data);
                file.compressed_blocks = std::move(compressed.blocks);
            } else {
                file.on_disk_data = file.data;
            }
        }
    }

    std::uint64_t conservative_data_size = 0;
    for (const auto* file : afid_files) {
        if (file->store_raw) {
            conservative_data_size = align_up(conservative_data_size, block_size);
        }
        conservative_data_size += file->on_disk_data.size();
        if (file->whole_block_raw) {
            conservative_data_size = align_up(conservative_data_size, block_size);
        }
    }
    const auto data_blocks = align_up(conservative_data_size, block_size) / block_size;
    build_dirents(*root);

    const std::uint64_t metadata_base_block = data_blocks + 63;
    const std::int64_t logical_blocks = static_cast<std::int64_t>(metadata_base_block + 5 + preorder.size());
    std::uint64_t meta_cursor = metadata_base_block * block_size;
    std::vector<MetaNode> nodes;
    nodes.push_back(MetaNode{"", super_root_inode, true, 0, meta_cursor, static_cast<std::int64_t>(block_size), 16749, 1, 131088, -1, -1});
    meta_cursor += block_size;
    nodes.push_back(meta_file(inode_flt_inode, meta_cursor, 131088, "inode_flat_path_table"));
    meta_cursor += block_size;
    nodes.push_back(meta_file(apr_flt_inode, meta_cursor, 131088, "apr_flat_path_table"));
    meta_cursor += block_size;
    nodes.push_back(meta_file(afid_table_inode, meta_cursor, 131088, "afid_to_ino_table"));
    meta_cursor += block_size;
    for (auto* directory : preorder) {
        const bool is_root = directory == root.get();
        nodes.push_back(MetaNode{
            directory->name,
            directory->inode,
            true,
            0,
            meta_cursor,
            static_cast<std::int64_t>(block_size),
            static_cast<std::uint16_t>(is_root ? 16749 : 16744),
            static_cast<std::uint16_t>(2u + directory->directories.size() + (is_root ? 1u : 0u)),
            static_cast<std::uint32_t>(is_root ? 16u : 131088u),
            is_root ? -1 : static_cast<std::int32_t>(directory->parent->inode),
            is_root ? -1 : directory->dirent_offset});
        meta_cursor += block_size;
    }
    std::size_t app_file_count = 0;
    for (auto* file : inode_files) {
        const auto mode = static_cast<std::uint16_t>(file->sce_sys ? 33128u : 33133u);
        if (mode == 33133u) {
            ++app_file_count;
        }
        nodes.push_back(MetaNode{
            file->name,
            file->inode,
            false,
            file->afid,
            file->logical_offset,
            static_cast<std::int64_t>(file->data.size()),
            mode,
            1,
            static_cast<std::uint32_t>(0x10u | (executable_module(file->data) ? 64u : 32u) |
                (file->sce_sys ? 131072u : 0u)),
            static_cast<std::int32_t>(file->parent->inode),
            file->dirent_offset});
    }
    std::sort(nodes.begin(), nodes.end(), [](const MetaNode& left, const MetaNode& right) {
        return left.inode < right.inode;
    });

    std::vector<FlatEntry> inode_entries;
    std::vector<FlatEntry> apr_entries;
    for (auto* directory : preorder) {
        if (directory != root.get()) {
            inode_entries.push_back(FlatEntry{
                hash_path(directory->full_path),
                pack_inode_entry(directory->inode, true, false, 0)});
        }
    }
    for (auto* file : inode_files) {
        // SharpProspero marks application files as APR-subtree entries.  The
        // packed inode FLT bit is the inverse of that flag: application files
        // therefore have subtree=false and sce_sys files have subtree=true.
        const bool subtree_apr = !file->sce_sys;
        inode_entries.push_back(FlatEntry{
            hash_path(file->full_path),
            pack_inode_entry(file->inode, false, !subtree_apr, file->afid)});
        if (subtree_apr) {
            apr_entries.push_back(FlatEntry{
                hash_path(file->full_path),
                pack_apr_entry(static_cast<std::int64_t>(file->data.size()), file->afid)});
        }
    }
    auto inode_table = build_flat_table(std::move(inode_entries));
    auto apr_table = build_flat_table(std::move(apr_entries));
    std::vector<std::byte> afid_table;
    append_le32(afid_table, inode_files.front()->inode);
    for (auto* file : afid_files) {
        append_le32(afid_table, file->inode);
    }
    append_le32(afid_table, 0xFFFFFFFFu);
    append_le32(afid_table, 0xFFFFFFFFu);
    for (auto& node : nodes) {
        if (node.inode == inode_flt_inode) {
            node.size = static_cast<std::int64_t>(inode_table.size());
        } else if (node.inode == apr_flt_inode) {
            node.size = static_cast<std::int64_t>(apr_table.size());
        } else if (node.inode == afid_table_inode) {
            node.size = static_cast<std::int64_t>(afid_table.size());
        }
    }

    std::vector<Dirent> super_dirents{
        Dirent{inode_flt_inode, 2, "inode_flat_path_table"},
        Dirent{apr_flt_inode, 2, "apr_flat_path_table"},
        Dirent{afid_table_inode, 2, "afid_to_ino_table"},
        Dirent{root->inode, 3, "uroot"}};
    std::vector<std::vector<std::byte>> metadata_blocks;
    metadata_blocks.push_back(serialize_dirents(super_dirents));
    metadata_blocks.push_back(std::move(inode_table));
    metadata_blocks.push_back(std::move(apr_table));
    metadata_blocks.push_back(std::move(afid_table));
    for (auto* directory : preorder) {
        metadata_blocks.push_back(serialize_dirents(directory->dirents));
    }
    metadata_blocks.emplace_back();
    auto metadata = build_metadata(nodes, logical_blocks, metadata_blocks, timestamp_seconds, timestamp_nanoseconds);
    // SharpProspero exposes the logical beginning of the metadata plaintext,
    // not the reserved-region boundary.  This is the value consumed by FIH
    // nestedMetaBaseBlocks and by NAPS hole/metadata ranges.
    const auto metadata_base_logical =
        static_cast<std::uint64_t>(logical_blocks) * block_size - metadata.size();
    auto compressed_metadata = compress_payload(metadata);
    const bool metadata_is_compressed = compressed_metadata.data.size() <= ((metadata.size() * 15u) >> 4u);
    std::vector<std::byte> metadata_payload = metadata_is_compressed
        ? std::move(compressed_metadata.data)
        : metadata;
    std::vector<InnerPfsBlockPlacement> metadata_chunk_placements = metadata_is_compressed
        ? std::move(compressed_metadata.blocks)
        : std::vector<InnerPfsBlockPlacement>{};

    std::vector<std::byte> image;
    std::uint64_t disk_cursor = 0;
    for (auto* file : afid_files) {
        const auto remainder = disk_cursor % block_size;
        const bool align_before = file->whole_block_raw ||
            (file->store_raw && remainder != 0 && file->on_disk_data.size() > block_size - remainder);
        if (align_before) {
            disk_cursor = align_up(disk_cursor, block_size);
            image.resize(static_cast<std::size_t>(disk_cursor));
        }
        file->on_disk_offset = disk_cursor;
        image.insert(image.end(), file->on_disk_data.begin(), file->on_disk_data.end());
        disk_cursor += file->on_disk_data.size();
        if (file->whole_block_raw) {
            disk_cursor = align_up(disk_cursor, block_size);
            image.resize(static_cast<std::size_t>(disk_cursor));
        }
    }
    std::uint64_t app_size = 0;
    for (const auto* file : afid_files) {
        if (!file->sce_sys) {
            app_size += file->data.size();
        }
    }
    disk_cursor = align_up(disk_cursor, block_size);
    image.resize(static_cast<std::size_t>(disk_cursor));
    const auto info = block_info_table(app_size);
    const auto block_info_on_disk = disk_cursor;
    image.insert(image.end(), info.begin(), info.end());
    disk_cursor += info.size();
    disk_cursor = align_up(disk_cursor, block_size);
    image.resize(static_cast<std::size_t>(disk_cursor));
    const auto metadata_on_disk = disk_cursor;
    image.insert(image.end(), metadata_payload.begin(), metadata_payload.end());
    if (metadata_chunk_placements.empty()) {
        for (std::uint64_t offset = 0; offset < metadata.size(); offset += 0x40000u) {
            const auto size = std::min<std::uint64_t>(0x40000u, metadata.size() - offset);
            metadata_chunk_placements.push_back(InnerPfsBlockPlacement{
                offset, offset, size, size, false, false, size});
        }
    }
    for (auto& chunk : metadata_chunk_placements) {
        chunk.on_disk_offset += metadata_on_disk;
        chunk.logical_offset += metadata_base_logical;
    }

    std::vector<InnerPfsPlacement> placements;
    placements.reserve(afid_files.size());
    std::vector<std::uint64_t> afid_logical_offsets(afid_files.size());
    std::vector<std::string> afid_paths(afid_files.size());
    for (const auto* file : afid_files) {
        placements.push_back(InnerPfsPlacement{
            file->on_disk_offset,
            file->logical_offset,
            static_cast<std::uint64_t>(file->on_disk_data.size()),
            static_cast<std::uint64_t>(file->data.size()),
            file->store_raw,
            file->compressed_blocks});
        if (file->afid >= afid_logical_offsets.size()) {
            throw std::runtime_error("PFS AFID placement index is out of range");
        }
        afid_logical_offsets[file->afid] = file->logical_offset;
        afid_paths[file->afid] = file->full_path.substr(1);
    }

    // FIH's nwonlyInnerContentInodes is the count of nodes that belong to the
    // mounted content tree.  Sharp excludes the super-root and the internal
    // metadata inodes (all of which have ParentInode < 0).
    const auto inner_content_inodes = static_cast<std::size_t>(std::count_if(
        nodes.begin(), nodes.end(), [](const MetaNode& node) { return node.parent_inode >= 0; }));

    return InnerPfsLayout{
        std::move(image),
        logical_blocks,
        static_cast<std::int64_t>(logical_blocks * block_size - metadata.size()),
        inner_content_inodes,
        app_file_count,
        std::move(placements),
        std::move(afid_logical_offsets),
        std::move(afid_paths),
        block_info_on_disk,
        metadata_on_disk,
        logical_cursor,
        metadata_base_logical,
        std::move(metadata_chunk_placements),
        std::move(metadata)};
}

} // namespace prosperopkg
