// Native debug SI (install metadata) archive builder.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/si.hpp>

#include <prosperopkg/aes_xts.hpp>
#include <prosperopkg/crc32c.hpp>
#include <prosperopkg/hash.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace prosperopkg {
namespace {

constexpr std::size_t block_size = 0x10000;
constexpr std::size_t ublock_size = 0x40000;
constexpr std::uint64_t meta_kind = 0x3E9;
constexpr std::array<std::byte, 16> meta_data_key{
    std::byte{0x02}, std::byte{0x2D}, std::byte{0xCA}, std::byte{0xF6},
    std::byte{0xD1}, std::byte{0x11}, std::byte{0xE5}, std::byte{0x8F},
    std::byte{0x25}, std::byte{0x93}, std::byte{0x6E}, std::byte{0xF5},
    std::byte{0x46}, std::byte{0x93}, std::byte{0x45}, std::byte{0xAB}};
constexpr std::array<std::byte, 16> meta_tweak_key{
    std::byte{0xAD}, std::byte{0xAC}, std::byte{0x16}, std::byte{0x37},
    std::byte{0x60}, std::byte{0xDA}, std::byte{0x51}, std::byte{0x46},
    std::byte{0x98}, std::byte{0xC2}, std::byte{0x45}, std::byte{0xAB},
    std::byte{0x4C}, std::byte{0x9C}, std::byte{0x42}, std::byte{0x6C}};
constexpr std::array<std::byte, 16> meta_tweak{
    std::byte{0x3C}, std::byte{0xBA}, std::byte{0x10}, std::byte{0x7D},
    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
    std::byte{0}, std::byte{0}};

void le32(std::vector<std::byte>& out, std::size_t at, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) out[at + i] = static_cast<std::byte>(value >> (8u * i));
}

void le64(std::vector<std::byte>& out, std::size_t at, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) out[at + i] = static_cast<std::byte>(value >> (8u * i));
}

void append_le32(std::vector<std::byte>& out, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>(value >> (8u * i)));
}

void append_le64(std::vector<std::byte>& out, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<std::byte>(value >> (8u * i)));
}

void append_record(std::vector<std::byte>& out, std::string_view tag,
    std::span<const std::byte> payload, std::uint8_t version = 1)
{
    if (tag.size() != 4) throw std::invalid_argument("NAPS metadata tag must be four bytes");
    out.push_back(static_cast<std::byte>(tag[3]));
    out.push_back(static_cast<std::byte>(tag[2]));
    out.push_back(static_cast<std::byte>(tag[1]));
    out.push_back(static_cast<std::byte>(tag[0]));
    out.push_back(static_cast<std::byte>(version));
    out.insert(out.end(), 3, std::byte{});
    append_le64(out, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
}

void gf_mul_alpha(std::array<std::byte, 16>& tweak)
{
    unsigned carry = 0;
    for (auto& b : tweak) {
        const auto value = static_cast<unsigned char>(b);
        b = static_cast<std::byte>((value << 1u) | carry);
        carry = (value >> 7u) & 1u;
    }
    if (carry != 0) tweak[0] ^= std::byte{0x87};
}

std::vector<std::byte> encrypt_meta18(std::vector<std::byte> plain)
{
    if ((plain.size() % 16u) != 0) throw std::runtime_error("NAPS metadata is not AES block aligned");
    auto tweak = aes128_encrypt_block(meta_tweak_key, meta_tweak);
    for (std::size_t at = 0; at < plain.size(); at += 16) {
        std::array<std::byte, 16> x{};
        for (std::size_t i = 0; i < 16; ++i) x[i] = plain[at + i] ^ tweak[i];
        const auto encrypted = aes128_encrypt_block(meta_data_key, x);
        for (std::size_t i = 0; i < 16; ++i) plain[at + i] = encrypted[i] ^ tweak[i];
        gf_mul_alpha(tweak);
    }
    return plain;
}

std::vector<std::byte> meta300(std::uint64_t inner_size)
{
    if (inner_size < block_size) throw std::invalid_argument("inner image is smaller than one PFS block");
    const auto r = inner_size - block_size;
    std::vector<std::byte> out(48);
    le64(out, 0x10, r); le64(out, 0x18, meta_kind); le64(out, 0x20, r); le64(out, 0x28, block_size);
    return out;
}

struct MetaBlock {
    std::uint64_t co = 0;
    std::uint32_t cs = 0, ps = 0, c0 = 0, c1 = 0, flag = 0;
    bool hole = false;
    std::uint32_t owner = 0;
    std::uint64_t tail = 0;
    std::uint64_t disk = 0;
    std::uint32_t disk_size = 0;
};

std::vector<MetaBlock> build_blocks(const InnerPfsLayout& inner)
{
    std::vector<MetaBlock> blocks;
    for (std::size_t i = 0; i < inner.placements.size(); ++i) {
        const auto& p = inner.placements[i];
        const auto owner = i == 0 ? 0u : 1u;
        // The SI file table describes the same AFID raw extents as the native
        // naps_pkg_layout builder: one extent per content file. Compressed
        // placement details stay in the PFS/NAPS descriptor and must not add
        // extra file-table entries here.
        blocks.push_back(MetaBlock{p.on_disk_offset, static_cast<std::uint32_t>(p.on_disk_size),
            static_cast<std::uint32_t>(p.uncompressed_size), static_cast<std::uint32_t>(p.on_disk_size), 0,
            0x40090000u, false, owner, 0, p.on_disk_offset, static_cast<std::uint32_t>(p.on_disk_size)});
    }

    const auto padding = inner.metadata_base_logical > inner.data_end_logical
        ? inner.metadata_base_logical - inner.data_end_logical : 0;
    std::array<std::pair<std::uint32_t, std::uint64_t>, 8> hole_offsets{};
    std::size_t hole_count = 0;
    auto hole_for = [&](std::uint32_t size) {
        for (std::size_t i = 0; i < hole_count; ++i) if (hole_offsets[i].first == size) return hole_offsets[i].second;
        if (hole_count >= hole_offsets.size()) throw std::runtime_error("too many NAPS hole sizes");
        const auto value = inner.block_info_on_disk_offset + hole_count * 0x10ull;
        hole_offsets[hole_count++] = {size, value};
        return value;
    };
    for (std::uint64_t at = 0; at < padding; at += ublock_size) {
        const auto ps = static_cast<std::uint32_t>(std::min<std::uint64_t>(ublock_size, padding - at));
        blocks.push_back(MetaBlock{hole_for(ps), 0x10, ps, 8, 8, 0x40110000u, true, 0, 0, 0, 0});
    }
    auto meta_cursor = inner.metadata_on_disk_offset;
    for (const auto& m : inner.metadata_blocks) {
        const auto c0 = m.multi_chunk ? m.first_chunk_compressed_size : m.on_disk_size;
        const auto c1 = m.multi_chunk ? m.on_disk_size - c0 : 0;
        blocks.push_back(MetaBlock{meta_cursor, static_cast<std::uint32_t>(m.on_disk_size),
            static_cast<std::uint32_t>(m.uncompressed_size), static_cast<std::uint32_t>(c0),
            static_cast<std::uint32_t>(c1), c1 ? 0x40450000u : 0x40050000u, false, 0, meta_kind,
            meta_cursor, static_cast<std::uint32_t>(m.on_disk_size)});
        meta_cursor += m.on_disk_size;
    }
    return blocks;
}

std::vector<std::byte> build_meta18(const SiBuildOptions& o, const std::vector<MetaBlock>& blocks)
{
    std::vector<std::byte> plain;
    const auto inner_blocks = static_cast<std::uint32_t>(o.inner_image_size / block_size);
    std::vector<std::uint32_t> first_file;
    if (o.inner != nullptr) {
        std::size_t block_index = 0;
        for (std::size_t i = 0; i < o.inner->placements.size(); ++i) {
            first_file.push_back(static_cast<std::uint32_t>(block_index));
            ++block_index;
        }
    }
    auto desc = meta300(o.inner_image_size);
    std::vector<std::byte> phdr(0x18);
    le32(phdr, 0, 1); le32(phdr, 4, 0x30); le32(phdr, 8, inner_blocks);
    le32(phdr, 12, static_cast<std::uint32_t>(o.inner_image_size)); le32(phdr, 16, 1); le32(phdr, 20, block_size);
    append_record(plain, "phdr", phdr);

    std::vector<std::byte> file_table(o.content_files.size() * 0x18);
    for (std::size_t i = 0; i < o.content_files.size(); ++i) {
        const bool metadata = o.content_files[i].path == "*PFSmetadata";
        const auto index = metadata ? static_cast<std::uint32_t>(blocks.size() - o.inner->metadata_blocks.size())
            : (i < first_file.size() ? first_file[i] : static_cast<std::uint32_t>(i));
        le64(file_table, i * 0x18, o.content_files[i].size);
        le32(file_table, i * 0x18 + 8, index); le32(file_table, i * 0x18 + 12, metadata ? 3u : 1u);
        le32(file_table, i * 0x18 + 16, metadata ? static_cast<std::uint32_t>(meta_kind) : 0u);
        le32(file_table, i * 0x18 + 20, metadata ? 0u : (i == 0 ? 0u : 1u));
    }
    append_record(plain, "file", file_table, 2);

    std::vector<std::byte> ibcl(blocks.size());
    std::size_t placement_blocks = 0;
    for (std::size_t i = 0; i < (o.inner ? o.inner->placements.size() : 0); ++i) {
        if (placement_blocks < ibcl.size()) ibcl[placement_blocks] = i == 0 ? std::byte{0x0F} : std::byte{1};
        ++placement_blocks;
    }
    std::fill(ibcl.begin() + static_cast<std::ptrdiff_t>(placement_blocks), ibcl.end(), std::byte{0x0F});
    append_record(plain, "ibcl", ibcl);

    std::vector<std::byte> i2ob(blocks.size() * 0x28), i2op(blocks.size() * 0x10), ihsh(blocks.size() * 0x30);
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const auto& b = blocks[i];
        le64(i2ob, i * 0x28, b.co); le32(i2ob, i * 0x28 + 8, b.cs); le32(i2ob, i * 0x28 + 12, b.ps);
        le32(i2ob, i * 0x28 + 16, b.c0); le32(i2ob, i * 0x28 + 20, b.c1); le32(i2ob, i * 0x28 + 24, static_cast<std::uint32_t>(b.co >> 16));
        le32(i2ob, i * 0x28 + 32, 1); le32(i2ob, i * 0x28 + 36, b.flag);
        le64(i2op, i * 0x10, b.co); le64(i2op, i * 0x10 + 8, b.co >> 16);
        std::array<std::byte, 32> digest{};
        if (b.hole) {
            std::vector<std::byte> zeros(b.ps);
            digest = sha3_256(zeros);
            le32(ihsh, i * 0x30, 0); le32(ihsh, i * 0x30 + 4, b.ps);
        } else if (o.inner != nullptr && b.disk + b.disk_size <= o.inner->image.size()) {
            digest = sha3_256(std::span<const std::byte>(o.inner->image).subspan(b.disk, b.disk_size));
        }
        std::copy(digest.begin(), digest.end(), ihsh.begin() + static_cast<std::ptrdiff_t>(i * 0x30 + 8));
        le64(ihsh, i * 0x30 + 0x28, b.tail);
    }
    append_record(plain, "i2ob", i2ob); append_record(plain, "i2op", i2op); append_record(plain, "ihsh", ihsh);

    std::vector<std::byte> rhsh(0xB0);
    const auto sb_off = block_size + o.outer_superblock_index * block_size;
    if (sb_off + block_size <= o.mount_image.size()) {
        const auto d = sha3_256(o.mount_image.subspan(sb_off, block_size));
        std::copy(d.begin(), d.end(), rhsh.begin());
    }
    append_record(plain, "rhsh", rhsh);
    std::vector<std::byte> fstr;
    for (const auto& file : o.content_files) {
        fstr.insert(fstr.end(), reinterpret_cast<const std::byte*>(file.path.data()),
            reinterpret_cast<const std::byte*>(file.path.data() + file.path.size()));
        fstr.push_back(std::byte{});
    }
    append_record(plain, "fstr", fstr);
    std::vector<std::byte> twek(0x14); le32(twek, 4, 4); append_record(plain, "twek", twek);
    std::vector<std::byte> obdg(0x80);
    const auto outer_digest = sha3_256(o.mount_image); std::copy(outer_digest.begin(), outer_digest.end(), obdg.begin());
    append_record(plain, "obdg", obdg);
    append_record(plain, "pgpl", desc); append_record(plain, "pgil", desc); append_record(plain, "pgpi", desc); append_record(plain, "pgpu", desc);
    const auto pad = (16u - (plain.size() % 16u)) % 16u;
    append_record(plain, "zero", std::vector<std::byte>(pad));
    return encrypt_meta18(std::move(plain));
}

std::uint32_t zip_crc(std::span<const std::byte> data)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const auto value : data) {
        crc ^= static_cast<std::uint8_t>(value);
        for (unsigned i = 0; i < 8; ++i) crc = (crc >> 1u) ^ (0xEDB88320u & static_cast<std::uint32_t>(-(static_cast<int>(crc & 1u))));
    }
    return ~crc;
}

struct Member { std::string path; std::vector<std::byte> data; };

std::vector<std::byte> write_zip(const std::vector<Member>& members)
{
    std::vector<std::byte> out;
    struct Local { std::uint32_t crc; std::uint32_t size; std::uint32_t offset; };
    std::vector<Local> locals;
    auto put16 = [&](std::uint16_t v) { out.push_back(static_cast<std::byte>(v)); out.push_back(static_cast<std::byte>(v >> 8)); };
    auto put32 = [&](std::uint32_t v) { for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>(v >> (i * 8u))); };
    for (const auto& m : members) {
        if (m.path.size() > 0xFFFF || m.data.size() > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("SI ZIP member too large");
        const auto off = static_cast<std::uint32_t>(out.size()), size = static_cast<std::uint32_t>(m.data.size());
        const auto crc = zip_crc(m.data); locals.push_back({crc, size, off});
        put32(0x04034B50); put16(20); put16(0); put16(0); put16(0); put16(0x21); put32(crc); put32(size); put32(size); put16(static_cast<std::uint16_t>(m.path.size())); put16(0);
        out.insert(out.end(), reinterpret_cast<const std::byte*>(m.path.data()), reinterpret_cast<const std::byte*>(m.path.data() + m.path.size())); out.insert(out.end(), m.data.begin(), m.data.end());
    }
    const auto cd_start = static_cast<std::uint32_t>(out.size());
    for (std::size_t i = 0; i < members.size(); ++i) {
        const auto& m = members[i]; const auto l = locals[i];
        put32(0x02014B50); put16(0); put16(20); put16(0); put16(0); put16(0); put16(0x21); put32(l.crc); put32(l.size); put32(l.size); put16(static_cast<std::uint16_t>(m.path.size())); put16(0); put16(0); put16(0); put16(0); put32(0); put32(l.offset);
        out.insert(out.end(), reinterpret_cast<const std::byte*>(m.path.data()), reinterpret_cast<const std::byte*>(m.path.data() + m.path.size()));
    }
    const auto cd_size = static_cast<std::uint32_t>(out.size() - cd_start);
    put32(0x06054B50); put16(0); put16(0); put16(static_cast<std::uint16_t>(members.size())); put16(static_cast<std::uint16_t>(members.size())); put32(cd_size); put32(cd_start); put16(0);
    return out;
}

std::string hex_digest(std::span<const std::byte> digest)
{
    constexpr char digits[] = "0123456789abcdef"; std::string out;
    for (std::size_t i = 0; i < digest.size(); ++i) { if (i) out += (i % 16 == 0 ? "\n" : " "); out += "0x"; out += digits[static_cast<std::uint8_t>(digest[i]) >> 4]; out += digits[static_cast<std::uint8_t>(digest[i]) & 15]; }
    return out;
}

std::string xml_escape(std::string_view value)
{
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '\"': out += "&quot;"; break;
        case '\'': out += "&apos;"; break;
        default: out.push_back(ch); break;
        }
    }
    return out;
}

std::vector<std::byte> build_xml(const SiBuildOptions& o, std::span<const std::byte> sb_digest,
    std::span<const std::byte> fixed_digest)
{
    if (o.mount_image.size() < block_size || o.pfs_image_size > o.mount_image.size() - block_size) {
        throw std::invalid_argument("SI mount image is smaller than its FIH and PFS regions");
    }
    const auto container_size = o.mount_image.size() - block_size - o.pfs_image_size;
    const auto package_size = o.mount_image.size();
    const auto body_size = container_size > 0x2000 ? container_size - 0x2000 : 0;
    const auto total = block_size + o.pfs_image_size + container_size;
    const auto zero_digest = hex_digest(std::array<std::byte, 32>{});
    std::array<std::byte, 16> pfs_seed{};
    const auto seed_offset = block_size + o.outer_superblock_index * block_size + 0x370;
    if (seed_offset + pfs_seed.size() <= o.mount_image.size()) {
        std::copy_n(o.mount_image.begin() + static_cast<std::ptrdiff_t>(seed_offset), pfs_seed.size(), pfs_seed.begin());
    }
    const auto seed_text = hex_digest(pfs_seed);
    const auto content_id = xml_escape(o.content_id);
    const auto version = xml_escape(o.version);
    const auto title = xml_escape(o.title);
    const auto master_version = o.version.size() == 10 && o.version[2] == '.' && o.version[6] == '.'
        ? o.version.substr(0, 2) + "." + o.version.substr(3, 2)
        : o.version;
    std::string version_digits;
    for (const char ch : o.version) if (ch != '.') version_digits.push_back(ch);
    const auto long_name = content_id + "-C" + version_digits + "-M0000000000000000-GD";
    std::string xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package-configuration version=\"1.0\" type=\"package-info\">\n";
    xml += "  <config version=\"" + version + "\" metadata=\"0\" primary=\"yes\">\n    <content-id>" + content_id + "</content-id>\n    <primary-id>" + content_id + "</primary-id>\n    <longname>" + long_name + "</longname>\n    <required-system-version>00.000.000.00000000</required-system-version>\n    <drm-type>none</drm-type>\n    <content-type>PS5GD</content-type>\n    <application-type>free</application-type>\n    <num-of-images>1</num-of-images>\n    <package-size>" + std::to_string(package_size) + "</package-size>\n    <version-date>0x20200722</version-date>\n    <version-hash>0x01fe52e9</version-hash>\n  </config>\n  <digests version=\"1.2\" major-param-version=\"0\">\n    <content-digest>" + zero_digest + "</content-digest><game-digest>\n      " + hex_digest(sb_digest) + "\n    </game-digest><header-digest>" + zero_digest + "</header-digest><system-digest>" + zero_digest + "</system-digest><param-digest>" + zero_digest + "</param-digest><package-digest>" + zero_digest + "</package-digest>\n  </digests>\n  <params><applicationDrmType>free</applicationDrmType><contentId>" + content_id + "</contentId><contentVersion>" + version + "</contentVersion><masterVersion>" + master_version + "</masterVersion><requiredSystemSoftwareVersion>0x0000000000000000</requiredSystemSoftwareVersion><sdkVersion>0x0000000000000000</sdkVersion><titleName>" + title + "</titleName></params>\n";
    xml += "  <container nth-of-image=\"1\"><container-size>0x" + [&]{ char b[32]; std::snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(container_size)); return std::string(b); }() + "</container-size><mandatory-size>0x" + [&]{ char b[32]; std::snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(o.mandatory_size)); return std::string(b); }() + "</mandatory-size><body-offset>0x0000000000002000</body-offset><body-size>0x" + [&]{ char b[32]; std::snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(body_size)); return std::string(b); }() + "</body-size><body-digest>" + zero_digest + "</body-digest><promote-size>0x" + [&]{ char b[32]; std::snprintf(b, sizeof(b), "%08llx", static_cast<unsigned long long>(container_size)); return std::string(b); }() + "</promote-size></container>\n";
    xml += "  <mount-image nth-of-image=\"1\" nested-image=\"yes\"><pfs-offset-align>0x0000000000010000</pfs-offset-align><pfs-size-align>0x0000000000010000</pfs-size-align><pfs-image-offset>0x0000000000010000</pfs-image-offset><pfs-image-size>0x";
    char pfsbuf[32]; std::snprintf(pfsbuf, sizeof(pfsbuf), "%016llx", static_cast<unsigned long long>(o.pfs_image_size)); xml += pfsbuf;
    xml += "</pfs-image-size><fixed-info-size>0x00010000</fixed-info-size><pfs-image-seed>" + seed_text + "</pfs-image-seed><sblock-digest>" + hex_digest(sb_digest) + "</sblock-digest><fixed-info-digest>" + hex_digest(fixed_digest) + "</fixed-info-digest><mount-image-offset>0x0000000000000000</mount-image-offset><mount-image-size>0x";
    char totalbuf[32]; std::snprintf(totalbuf, sizeof(totalbuf), "%016llx", static_cast<unsigned long long>(total)); xml += totalbuf; xml += "</mount-image-size><container-offset>0x"; char containerbuf[32]; std::snprintf(containerbuf, sizeof(containerbuf), "%016llx", static_cast<unsigned long long>(block_size + o.pfs_image_size)); xml += containerbuf; xml += "</container-offset><supplemental-offset>0x"; char supplbuf[32]; std::snprintf(supplbuf, sizeof(supplbuf), "%016llx", static_cast<unsigned long long>(container_size)); xml += supplbuf; xml += "</supplemental-offset></mount-image></package-configuration>\n";
    return std::vector<std::byte>(reinterpret_cast<const std::byte*>(xml.data()), reinterpret_cast<const std::byte*>(xml.data() + xml.size()));
}

} // namespace

std::vector<std::byte> build_si_archive(const SiBuildOptions& o)
{
    if (o.content_id.empty() || o.mount_image.empty() || o.inner == nullptr || o.inner_image_size < block_size) return {};
    if (o.mount_image.size() < block_size || o.pfs_image_size > o.mount_image.size() - block_size) {
        throw std::invalid_argument("SI mount image is smaller than its FIH and PFS regions");
    }
    const auto blocks = build_blocks(*o.inner);
    auto meta18 = build_meta18(o, blocks);
    auto desc = meta300(o.inner_image_size);
    const auto sb_off = block_size + o.outer_superblock_index * block_size;
    const auto sb_digest = sb_off + block_size <= o.mount_image.size() ? sha3_256(o.mount_image.subspan(sb_off, block_size)) : std::array<std::byte, 32>{};
    const auto fixed_digest = sha3_256(o.mount_image.first(std::min<std::size_t>(block_size, o.mount_image.size())));
    auto xml = build_xml(o, sb_digest, fixed_digest);
    std::vector<std::byte> crc;
    for (std::size_t at = 0; at < o.mount_image.size(); at += block_size) append_le32(crc, crc32c(o.mount_image.subspan(at, std::min(block_size, o.mount_image.size() - at))));
    std::vector<Member> members;
    members.push_back({"common/etc/naps_meta_18.dat", std::move(meta18)});
    for (const auto id : {300, 301, 302, 308}) members.push_back({"common/etc/naps_meta_" + std::to_string(id) + ".dat", desc});
    members.push_back({"common/etc/pfsimage.xml", std::move(xml)});
    if (!o.playgo_chunk_dat.empty()) members.push_back({"common/etc/playgo-chunk.dat", std::vector<std::byte>(o.playgo_chunk_dat.begin(), o.playgo_chunk_dat.end())});
    members.push_back({"config/" + o.content_id + "/playgo-chunk.crc", std::move(crc)});
    return write_zip(members);
}

} // namespace prosperopkg
