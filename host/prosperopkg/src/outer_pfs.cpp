#include <prosperopkg/outer_pfs.hpp>

#include <prosperopkg/hash.hpp>
#include <prosperopkg/pfs_image.hpp>
#include <prosperopkg/pfs_keys.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

namespace prosperopkg {
namespace {

constexpr std::size_t block_size = 0x10000;
constexpr std::size_t d32_size = 712;
constexpr std::size_t d64_size = 784;
constexpr std::size_t indirect_entries = 1820;
constexpr std::uint16_t mode_dir = 16749;
constexpr std::uint16_t mode_file = 33133;
constexpr std::uint32_t flags_internal = 131084;
constexpr std::uint32_t flags_dir = 12;
constexpr std::uint32_t flags_file = 13;
constexpr std::uint32_t dirent_file = 2;
constexpr std::uint32_t dirent_directory = 3;
constexpr std::uint32_t dirent_dot = 4;
constexpr std::uint32_t dirent_dotdot = 5;

void le16(std::span<std::byte> out, std::size_t at, std::uint16_t value)
{
    out[at] = static_cast<std::byte>(value);
    out[at + 1] = static_cast<std::byte>(value >> 8u);
}

void le32(std::span<std::byte> out, std::size_t at, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) out[at + i] = static_cast<std::byte>(value >> (i * 8u));
}

void le64(std::span<std::byte> out, std::size_t at, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) out[at + i] = static_cast<std::byte>(value >> (i * 8u));
}

[[nodiscard]] std::size_t align_blocks(std::size_t size)
{
    return std::max<std::size_t>(1, (size + block_size - 1) / block_size);
}

[[nodiscard]] std::size_t dirent_size(std::string_view name)
{
    return (name.size() + 24) & ~std::size_t{7};
}

void dirent(std::span<std::byte> block, std::size_t& cursor,
    std::uint32_t inode, std::uint32_t type, std::string_view name)
{
    const auto size = dirent_size(name);
    if (cursor + size > block.size()) throw std::runtime_error("outer PFS directory block overflow");
    le32(block, cursor, inode);
    le32(block, cursor + 4, type);
    le32(block, cursor + 8, static_cast<std::uint32_t>(name.size()));
    le32(block, cursor + 12, static_cast<std::uint32_t>(size));
    for (std::size_t i = 0; i < name.size(); ++i) block[cursor + 16 + i] = static_cast<std::byte>(name[i]);
    cursor += size;
}

[[nodiscard]] std::uint64_t rotl(std::uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }
[[nodiscard]] std::uint64_t rotr(std::uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

[[nodiscard]] std::uint64_t flt_hash(std::string_view name)
{
    constexpr std::uint64_t seed = 10577419142525243217ull;
    constexpr std::uint64_t rc = 0x8000000080008081ull;
    std::vector<std::byte> bytes;
    for (char c : name) bytes.push_back(static_cast<std::byte>(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c));
    std::uint64_t a = seed, b = rotl(seed, 11), c = rotl(seed, 23), tail = 0;
    std::size_t offset = 0;
    while (bytes.size() - offset > 8) {
        std::uint64_t word = 0;
        for (unsigned i = 0; i < 8; ++i) word |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8u);
        a ^= word;
        const auto x = rotr(rotl(c ^ b, 5) ^ a, 11);
        const auto y = rotl(rotl(c ^ a, 17) ^ b, 11);
        const auto z = rotr(rotl(b ^ a, 1) ^ c, 5);
        a = (~y & z) ^ x ^ rc; b = (~z & x) ^ y; c = (~x & y) ^ z; offset += 8;
    }
    for (std::size_t i = offset; i < bytes.size(); ++i) tail |= static_cast<std::uint64_t>(bytes[i]) << ((i - offset) * 8u);
    const auto mixed = tail ^ a ^ 0x09BBB761A41BC44Dull;
    const auto x = rotl(c ^ b, 5) ^ mixed;
    const auto y = rotl(c ^ mixed, 17) ^ b;
    const auto z = rotl(b ^ mixed, 1) ^ c;
    return (~rotl(y, 11) & rotr(z, 5)) ^ rotr(x, 11) ^ rc;
}

void write_sig(std::span<std::byte> out, std::size_t at, std::span<const std::byte> digest, std::int64_t block)
{
    std::copy(digest.begin(), digest.end(), out.begin() + static_cast<std::ptrdiff_t>(at));
    le32(out, at + 32, static_cast<std::uint32_t>(block));
}

void stamp(std::span<std::byte> inode, std::int64_t seconds, std::uint32_t nanoseconds)
{
    for (unsigned i = 0; i < 4; ++i) le64(inode, 24 + i * 8, static_cast<std::uint64_t>(seconds));
    for (unsigned i = 0; i < 4; ++i) le32(inode, 56 + i * 4, nanoseconds);
}

void write_d32(std::span<std::byte> out, std::size_t at, std::uint16_t mode, std::uint16_t nlink,
    std::uint32_t flags, std::uint64_t size, std::uint64_t compressed, std::uint32_t blocks,
    std::int64_t seconds, std::uint32_t nanos)
{
    auto inode = out.subspan(at, d32_size);
    std::fill(inode.begin(), inode.end(), std::byte{});
    le16(inode, 0, mode); le16(inode, 2, nlink); le32(inode, 4, flags);
    le64(inode, 8, size); le64(inode, 16, compressed); stamp(inode, seconds, nanos);
    le32(inode, 72, 0); le32(inode, 76, 0); le64(inode, 80, 0); le64(inode, 88, 0); le32(inode, 96, blocks);
}

void write_superblock_inode(std::span<std::byte> out, std::size_t at, std::int64_t seconds,
    std::span<const std::byte> inode_hash, std::size_t inode_block)
{
    auto inode = out.subspan(at, d64_size);
    std::fill(inode.begin(), inode.end(), std::byte{});
    le16(inode, 0, 0); le16(inode, 2, 1); le32(inode, 4, 0);
    le64(inode, 8, block_size); le64(inode, 16, block_size); stamp(inode, seconds, 0);
    le32(inode, 96, 1); le32(inode, 100, 0);
    write_sig(inode, 104, inode_hash, static_cast<std::int64_t>(inode_block));
    for (std::size_t i = 1; i < 17; ++i) le64(inode, 104 + i * 40 + 32, std::numeric_limits<std::uint64_t>::max());
}

} // namespace

OuterPfsPackageImage build_outer_pfs_for_package(std::vector<OuterPfsFile> files,
    const OuterPfsBuildParameters& parameters, std::span<const std::byte> ekpfs)
{
    if (files.empty()) throw std::invalid_argument("outer PFS requires at least one file");
    if (ekpfs.size() != 32) throw std::invalid_argument("EKPFS must be 32 bytes");
    std::vector<std::size_t> first(files.size()), blocks(files.size());
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < files.size(); ++i) { first[i] = cursor; blocks[i] = align_blocks(files[i].data.size()); cursor += blocks[i]; }
    const auto super = cursor++, inode_block = cursor++, root_block = cursor++, flt_block = cursor++;
    std::vector<std::size_t> indirect(files.size(), std::numeric_limits<std::size_t>::max());
    for (std::size_t i = 0; i < files.size(); ++i) if (blocks[i] > 12) {
        const auto count = (blocks[i] - 12 + indirect_entries - 1) / indirect_entries;
        if (count > 5) throw std::invalid_argument("outer PFS file exceeds five indirect blocks");
        indirect[i] = cursor; cursor += count;
    }
    const auto uroot = cursor++;
    std::vector<std::byte> image(cursor * block_size);
    for (std::size_t i = 0; i < files.size(); ++i) std::copy(files[i].data.begin(), files[i].data.end(), image.begin() + static_cast<std::ptrdiff_t>(first[i] * block_size));

    auto root_span = std::span<std::byte>(image).subspan(root_block * block_size, block_size); std::size_t pos = 0;
    dirent(root_span, pos, 1, dirent_file, "inode_flat_path_table");
    dirent(root_span, pos, 2, dirent_directory, "uroot");
    auto uroot_span = std::span<std::byte>(image).subspan(uroot * block_size, block_size); pos = 0;
    dirent(uroot_span, pos, 2, dirent_dot, ".");
    dirent(uroot_span, pos, 2, dirent_dotdot, "..");
    for (std::size_t i = 0; i < files.size(); ++i)
        dirent(uroot_span, pos, static_cast<std::uint32_t>(3 + i), dirent_file, files[i].name);
    auto flt_span = std::span<std::byte>(image).subspan(flt_block * block_size, block_size); le32(flt_span, 0, 1); le32(flt_span, 4, 16); le32(flt_span, 8, 64); flt_span[32]=std::byte{0x7f}; flt_span[33]=std::byte{'F'}; flt_span[34]=std::byte{'L'}; flt_span[35]=std::byte{'T'}; le32(flt_span, 44, static_cast<std::uint32_t>(files.size())); le64(flt_span, 48, 10577419142525243217ull); le64(flt_span, 56, 701355796979237965ull);
    // The outer-PFS builder preserves the supplied file order in its FLT.
    // (The nested PS5 FLTs are hash-sorted, but this outer table is not.)
    for (std::size_t i = 0; i < files.size(); ++i) {
        const auto hash = flt_hash(files[i].name);
        const auto packed = static_cast<std::uint64_t>(3 + i) |
            (static_cast<std::uint64_t>(i) << 40);
        le64(flt_span, 64 + i * 16, hash);
        le64(flt_span, 72 + i * 16, packed);
    }

    auto hash_block = [&](std::size_t block) { return sha3_256(std::span<const std::byte>(image).subspan(block * block_size, block_size)); };
    auto inode_span = std::span<std::byte>(image).subspan(inode_block * block_size, block_size);
    write_d32(inode_span, 0 * d32_size, mode_dir, 1, flags_internal, block_size, block_size, 1, parameters.timestamp_seconds, parameters.timestamp_nanoseconds);
    write_sig(inode_span, 100, hash_block(root_block), static_cast<std::int64_t>(root_block));
    write_d32(inode_span, 1 * d32_size, mode_file, 1, flags_internal, 64 + files.size() * 16, 64 + files.size() * 16, 1, parameters.timestamp_seconds, parameters.timestamp_nanoseconds); write_sig(inode_span, d32_size + 100, hash_block(flt_block), static_cast<std::int64_t>(flt_block));
    write_d32(inode_span, 2 * d32_size, mode_dir, 3, flags_dir, block_size, block_size, 1, parameters.timestamp_seconds, parameters.timestamp_nanoseconds); write_sig(inode_span, 2 * d32_size + 100, hash_block(uroot), static_cast<std::int64_t>(uroot));
    for (std::size_t i = 0; i < files.size(); ++i) {
        const auto at = (3 + i) * d32_size; const auto n = blocks[i];
        write_d32(inode_span, at, mode_file, 1, flags_file, files[i].data.size(), files[i].size_compressed ? files[i].size_compressed : files[i].data.size(), static_cast<std::uint32_t>(n), parameters.timestamp_seconds, parameters.timestamp_nanoseconds);
        const auto direct = std::min<std::size_t>(n, 12); for (std::size_t j = 0; j < direct; ++j) write_sig(inode_span, at + 100 + j * 36, hash_block(first[i] + j), static_cast<std::int64_t>(first[i] + j));
        for (std::size_t j = 12; j < n; ++j) { const auto ib = indirect[i] + (j - 12) / indirect_entries; const auto slot = (j - 12) % indirect_entries; auto iblock = std::span<std::byte>(image).subspan(ib * block_size, block_size); write_sig(iblock, slot * 36, hash_block(first[i] + j), static_cast<std::int64_t>(first[i] + j)); }
        if (n > 12) for (std::size_t j = 0; j < (n - 12 + indirect_entries - 1) / indirect_entries; ++j) write_sig(inode_span, at + 100 + (12 + j) * 36, hash_block(indirect[i] + j), static_cast<std::int64_t>(indirect[i] + j));
    }
    auto super_span = std::span<std::byte>(image).subspan(super * block_size, block_size); le64(super_span, 0, 2); le64(super_span, 8, 20130315); super_span[0x1A] = std::byte{1}; le16(super_span, 0x1C, 0xD); le32(super_span, 0x20, block_size); le64(super_span, 0x28, 1); le64(super_span, 0x30, 3 + files.size()); le64(super_span, 0x38, image.size() / block_size); le64(super_span, 0x40, 1); write_superblock_inode(super_span, 0x50, parameters.timestamp_seconds, hash_block(inode_block), inode_block); le32(super_span, 0x36C, 1); std::copy(parameters.seed.begin(), parameters.seed.end(), super_span.begin() + 0x370); std::fill(super_span.begin() + 896, super_span.begin() + 928, std::byte{}); auto icv = sha3_256(std::span<const std::byte>(super_span).first(1440)); std::copy(icv.begin(), icv.end(), super_span.begin() + 896); const auto super_digest = sha3_256(std::span<const std::byte>(super_span));
    std::vector<std::byte> digests(image.size() / block_size * 32); for (std::size_t i = 0; i < image.size() / block_size; ++i) { const auto h = hash_block(i); std::copy(h.begin(), h.end(), digests.begin() + static_cast<std::ptrdiff_t>(i * 32)); }
    const auto keys = derive_image_encryption_keys(ekpfs, parameters.seed); std::vector<OuterPfsBlockKind> kinds(image.size() / block_size, OuterPfsBlockKind::signed_block); for (std::size_t i = 0; i < files.size(); ++i) for (std::size_t j = 0; j < blocks[i]; ++j) kinds[first[i] + j] = files[i].signed_data ? OuterPfsBlockKind::signed_block : OuterPfsBlockKind::data; kinds[super] = OuterPfsBlockKind::plaintext; (void)transform_outer_pfs_image(image, keys, block_size, kinds, true);
    return OuterPfsPackageImage{std::move(image), std::move(digests), icv, super_digest, super};
}

} // namespace prosperopkg
