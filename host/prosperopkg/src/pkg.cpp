// LibProsperoPkg - A library for building and inspecting PS5 packages.
// C++ port/rewrite Copyright (C) 2026 seregonwar.
// Original C# LibProsperoPkg by SvenGDK.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/pkg.hpp>
#include <prosperopkg/hash.hpp>
#include <prosperopkg/image_digests.hpp>
#include <prosperopkg/pfs_keys.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <ios>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>
#include <cstdlib>
#include <string_view>

#include <boost/multiprecision/cpp_int.hpp>

namespace prosperopkg {
namespace {

[[nodiscard]] std::uint16_t read_be16(const std::byte* data) noexcept
{
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8u) |
        static_cast<std::uint16_t>(data[1]));
}

[[nodiscard]] std::uint32_t read_be32(const std::byte* data) noexcept
{
    return (static_cast<std::uint32_t>(data[0]) << 24u) |
           (static_cast<std::uint32_t>(data[1]) << 16u) |
           (static_cast<std::uint32_t>(data[2]) << 8u) |
           static_cast<std::uint32_t>(data[3]);
}

[[nodiscard]] std::uint64_t read_be64(const std::byte* data) noexcept
{
    return (static_cast<std::uint64_t>(read_be32(data)) << 32u) | read_be32(data + 4);
}

[[nodiscard]] std::uint32_t read_le32(const std::byte* data) noexcept
{
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8u) |
           (static_cast<std::uint32_t>(data[2]) << 16u) |
           (static_cast<std::uint32_t>(data[3]) << 24u);
}

[[nodiscard]] std::uint64_t read_le64(const std::byte* data) noexcept
{
    return static_cast<std::uint64_t>(read_le32(data)) |
           (static_cast<std::uint64_t>(read_le32(data + 4)) << 32u);
}

void write_be16(std::byte* data, std::uint16_t value) noexcept
{
    data[0] = static_cast<std::byte>((value >> 8u) & 0xFFu);
    data[1] = static_cast<std::byte>(value & 0xFFu);
}

void write_be32(std::byte* data, std::uint32_t value) noexcept
{
    data[0] = static_cast<std::byte>((value >> 24u) & 0xFFu);
    data[1] = static_cast<std::byte>((value >> 16u) & 0xFFu);
    data[2] = static_cast<std::byte>((value >> 8u) & 0xFFu);
    data[3] = static_cast<std::byte>(value & 0xFFu);
}

void write_be64(std::byte* data, std::uint64_t value) noexcept
{
    write_be32(data, static_cast<std::uint32_t>(value >> 32u));
    write_be32(data + 4, static_cast<std::uint32_t>(value & 0xFFFFFFFFu));
}

[[nodiscard]] std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment)
{
    return ((value + alignment - 1u) / alignment) * alignment;
}

[[nodiscard]] std::uint64_t stream_length(std::istream& stream)
{
    stream.clear();
    const auto original = stream.tellg();
    if (original == std::istream::pos_type(-1)) {
        throw std::runtime_error("Stream is not seekable.");
    }

    stream.seekg(0, std::ios::end);
    const auto end = stream.tellg();
    if (end == std::istream::pos_type(-1)) {
        throw std::runtime_error("Could not determine stream length.");
    }

    stream.seekg(original, std::ios::beg);
    return static_cast<std::uint64_t>(end);
}

void seek_abs(std::istream& stream, std::uint64_t offset)
{
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        throw std::runtime_error("Offset is too large for this platform stream.");
    }

    stream.clear();
    stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream) {
        throw std::runtime_error("Could not seek inside PS5 PKG stream.");
    }
}

void read_exact(std::istream& stream, std::byte* out, std::size_t size)
{
    stream.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));
    if (stream.gcount() != static_cast<std::streamsize>(size)) {
        throw std::runtime_error("Unexpected end of PS5 PKG while reading container.");
    }
}

[[nodiscard]] std::vector<std::byte> read_exact_at(
    std::istream& stream,
    std::uint64_t offset,
    std::size_t size)
{
    std::vector<std::byte> buffer(size);
    seek_abs(stream, offset);
    read_exact(stream, buffer.data(), buffer.size());
    return buffer;
}

[[nodiscard]] bool starts_with(
    const std::array<std::byte, 4>& actual,
    const std::array<std::byte, 4>& expected) noexcept
{
    return std::equal(actual.begin(), actual.end(), expected.begin());
}

[[nodiscard]] std::string read_nul_trimmed_ascii(const std::byte* data, std::size_t size)
{
    std::size_t len = 0;
    while (len < size && data[len] != std::byte{0}) {
        ++len;
    }
    return std::string(reinterpret_cast<const char*>(data), len);
}

[[nodiscard]] FihHeader read_fih_header(std::istream& stream)
{
    auto buffer = read_exact_at(stream, 0, 0x100);
    return FihHeader{
        static_cast<std::uint8_t>(buffer[PkgLayout::fih_signed_byte_offset]),
        read_le64(buffer.data() + PkgLayout::fih_pfs_image_offset_field),
        read_le64(buffer.data() + PkgLayout::fih_pfs_image_size_field),
        read_le64(buffer.data() + PkgLayout::fih_embedded_cnt_offset_field)};
}

[[nodiscard]] PkgHeader read_header(std::istream& stream, std::uint64_t base_offset)
{
    auto buffer = read_exact_at(stream, base_offset, PkgLayout::header_size);
    PkgHeader header{};
    std::copy_n(buffer.begin(), 4, header.magic.begin());
    header.flags = read_be32(buffer.data() + 0x04);
    header.entry_count = read_be32(buffer.data() + 0x10);
    header.sc_entry_count = read_be16(buffer.data() + 0x14);
    header.entry_table_offset = read_be32(buffer.data() + 0x18);
    header.body_offset = read_be64(buffer.data() + 0x20);
    header.body_size = read_be64(buffer.data() + 0x28);
    header.content_id = read_nul_trimmed_ascii(buffer.data() + 0x40, PkgLayout::content_id_size);
    header.drm_type = read_be32(buffer.data() + 0x70);
    header.content_type = read_be32(buffer.data() + 0x74);
    return header;
}

[[nodiscard]] std::vector<PkgEntry> read_entry_table(
    std::istream& stream,
    const PkgHeader& header,
    std::uint64_t base_offset)
{
    const std::uint64_t length = stream_length(stream);
    const std::uint64_t table_offset = base_offset + header.entry_table_offset;
    if (table_offset > length) {
        throw std::runtime_error("PS5 PKG entry table starts outside the stream.");
    }

    const std::uint64_t max_entries =
        (length - table_offset) / static_cast<std::uint64_t>(PkgLayout::entry_meta_size);
    if (header.entry_count > max_entries || header.entry_count > 0x10000u) {
        throw std::runtime_error("PS5 PKG entry table is malformed (entry count out of range).");
    }

    std::vector<PkgEntry> entries;
    entries.reserve(header.entry_count);
    auto record = std::array<std::byte, PkgLayout::entry_meta_size>{};
    seek_abs(stream, table_offset);

    for (std::uint32_t i = 0; i < header.entry_count; ++i) {
        read_exact(stream, record.data(), record.size());
        const std::uint32_t raw_id = read_be32(record.data());
        entries.push_back(PkgEntry{
            entry_id_from_raw(raw_id),
            raw_id,
            read_be32(record.data() + 0x04),
            read_be32(record.data() + 0x08),
            read_be32(record.data() + 0x0C),
            read_be32(record.data() + 0x10),
            read_be32(record.data() + 0x14),
            {}});
    }

    return entries;
}

void resolve_names(std::istream& stream, std::vector<PkgEntry>& entries, std::uint64_t base_offset)
{
    const auto it = std::find_if(entries.begin(), entries.end(), [](const PkgEntry& entry) {
        return entry.id == EntryId::entry_names;
    });
    if (it == entries.end() || it->data_size == 0) {
        return;
    }

    auto names = read_exact_at(stream, base_offset + it->data_offset, it->data_size);
    for (PkgEntry& entry : entries) {
        if (entry.name_table_offset == 0 || entry.name_table_offset >= names.size()) {
            continue;
        }

        std::size_t start = entry.name_table_offset;
        std::size_t end = start;
        while (end < names.size() && names[end] != std::byte{0}) {
            ++end;
        }

        entry.name.assign(
            reinterpret_cast<const char*>(names.data() + start),
            end - start);
    }
}

void write_ascii(std::vector<std::byte>& image, std::uint32_t offset, const std::string& value)
{
    if (offset + value.size() > image.size()) {
        throw std::runtime_error("Internal CNT writer offset overflow.");
    }
    std::memcpy(image.data() + offset, value.data(), value.size());
}

[[nodiscard]] std::vector<std::byte> read_key_file(const std::string& name)
{
    std::vector<std::filesystem::path> candidates;
    if (const char* dir = std::getenv("PROSPERO_PKG_KEYS_DIR")) {
        candidates.emplace_back(std::filesystem::path(dir) / name);
        candidates.emplace_back(std::filesystem::path(dir) / ("LibProsperoPkg.Keys.Data." + name));
    }
    if (const char* sdk = std::getenv("PS5_PAYLOAD_SDK")) {
        candidates.emplace_back(std::filesystem::path(sdk) / "share/prosperopkg/keys" / name);
    }
    candidates.emplace_back(std::filesystem::path("/opt/ps5-payload-sdk/share/prosperopkg/keys") / name);
    candidates.emplace_back(std::filesystem::path("/tmp/libprosperopkg-decomp") / ("LibProsperoPkg.Keys.Data." + name));
    for (const auto& path : candidates) {
        std::ifstream file(path, std::ios::binary);
        if (!file) continue;
        file.seekg(0, std::ios::end);
        const auto length = file.tellg();
        file.seekg(0, std::ios::beg);
        if (length <= 0) continue;
        std::vector<std::byte> data(static_cast<std::size_t>(length));
        file.read(reinterpret_cast<char*>(data.data()), length);
        if (file) return data;
    }
    throw std::runtime_error("Could not locate PS5 package key resource '" + name + "'. Set PROSPERO_PKG_KEYS_DIR.");
}

[[nodiscard]] std::vector<std::byte> rsa_pkcs1_encrypt(
    std::span<const std::byte> modulus,
    std::span<const std::byte> plaintext)
{
    if (modulus.size() != 384 || plaintext.size() > 373) {
        throw std::invalid_argument("Invalid RSA-3072 input size");
    }
    using boost::multiprecision::cpp_int;
    const std::size_t padding_size = modulus.size() - plaintext.size() - 3;
    if (padding_size < 8) throw std::invalid_argument("RSA PKCS#1 padding is too short");

    std::vector<std::byte> encoded(modulus.size());
    encoded[0] = std::byte{0};
    encoded[1] = std::byte{2};
    std::random_device random;
    for (std::size_t i = 0; i < padding_size; ++i) {
        unsigned value = 0;
        while (value == 0) value = random() & 0xffu;
        encoded[2 + i] = static_cast<std::byte>(value);
    }
    encoded[2 + padding_size] = std::byte{0};
    std::copy(plaintext.begin(), plaintext.end(), encoded.begin() + static_cast<std::ptrdiff_t>(3 + padding_size));

    auto import_be = [](std::span<const std::byte> bytes) {
        cpp_int value = 0;
        for (const auto byte : bytes) {
            value <<= 8;
            value += static_cast<unsigned>(byte);
        }
        return value;
    };
    const cpp_int n = import_be(modulus);
    if (n <= 0) throw std::invalid_argument("Invalid RSA modulus");
    cpp_int base = import_be(encoded) % n;
    cpp_int exponent = 65537;
    cpp_int result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) result = (result * base) % n;
        base = (base * base) % n;
        exponent >>= 1;
    }

    std::vector<std::byte> output(modulus.size());
    for (std::size_t i = output.size(); i-- > 0 && result != 0;) {
        output[i] = static_cast<std::byte>(static_cast<unsigned>(result & 0xff));
        result >>= 8;
    }
    return output;
}

[[nodiscard]] std::vector<std::byte> base64_decode(std::string_view text)
{
    std::array<int, 256> table{}; table.fill(-1);
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (std::size_t i = 0; i < alphabet.size(); ++i) table[static_cast<unsigned char>(alphabet[i])] = static_cast<int>(i);
    std::vector<std::byte> output; int value = 0, bits = -8;
    for (const char c : text) {
        if (c == '=') break; const int decoded = table[static_cast<unsigned char>(c)]; if (decoded < 0) continue;
        value = (value << 6) | decoded; bits += 6;
        if (bits >= 0) { output.push_back(static_cast<std::byte>((value >> bits) & 0xFF)); bits -= 8; }
    }
    return output;
}

[[nodiscard]] std::vector<std::byte> pem_rsa_modulus(std::span<const std::byte> pem)
{
    const std::string text(reinterpret_cast<const char*>(pem.data()), pem.size());
    const auto begin = text.find("-----BEGIN RSA PRIVATE KEY-----");
    const auto end = text.find("-----END RSA PRIVATE KEY-----");
    if (begin == std::string::npos || end == std::string::npos || end <= begin) throw std::runtime_error("Invalid RSA PEM");
    const auto body = text.substr(begin + 31, end - (begin + 31));
    const auto der = base64_decode(body);
    std::size_t p = 0;
    auto read_tlv = [&](std::size_t& at) {
        if (at >= der.size() || der[at++] != std::byte{0x02}) throw std::runtime_error("Invalid RSA DER");
        std::size_t length = static_cast<unsigned>(der[at++]);
        if (length & 0x80u) { const auto n = length & 0x7Fu; length = 0; for (unsigned i = 0; i < n; ++i) length = (length << 8) | static_cast<unsigned>(der[at++]); }
        if (at + length > der.size()) throw std::runtime_error("Invalid RSA DER length");
        const auto start = at; at += length; return std::pair<std::size_t, std::size_t>{start, length};
    };
    if (der.size() < 2 || der[p++] != std::byte{0x30}) throw std::runtime_error("Invalid RSA DER sequence");
    std::size_t sequence_length = static_cast<unsigned>(der[p++]);
    if (sequence_length & 0x80u) { const auto n = sequence_length & 0x7Fu; sequence_length = 0; for (unsigned i = 0; i < n; ++i) sequence_length = (sequence_length << 8) | static_cast<unsigned>(der[p++]); }
    (void)read_tlv(p);
    const auto modulus = read_tlv(p);
    std::vector<std::byte> result(der.begin() + static_cast<std::ptrdiff_t>(modulus.first), der.begin() + static_cast<std::ptrdiff_t>(modulus.first + modulus.second));
    while (result.size() > 1 && result.front() == std::byte{0}) result.erase(result.begin());
    return result;
}

[[nodiscard]] std::vector<std::byte> rsa_metadata_encrypt(std::span<const std::byte> plaintext)
{
    const auto pem = read_key_file("pkg_meta_rsa_key.pem");
    auto modulus = pem_rsa_modulus(pem);
    return rsa_pkcs1_encrypt(modulus, plaintext);
}

[[nodiscard]] std::vector<std::byte> reverse_digest_chunks(std::span<const std::byte> input)
{
    if (input.empty()) return {};
    if (input.size() % 32 != 0) throw std::invalid_argument("PFS image digest table is not 32-byte aligned");
    std::vector<std::byte> output(input.size());
    for (std::size_t i = 0; i < input.size(); i += 32) {
        std::reverse_copy(input.begin() + static_cast<std::ptrdiff_t>(i),
            input.begin() + static_cast<std::ptrdiff_t>(i + 32), output.begin() + static_cast<std::ptrdiff_t>(i));
    }
    return output;
}

} // namespace

std::uint32_t PkgEntry::key_index() const noexcept
{
    return (flags2 & 0xF000u) >> 12u;
}

bool PkgEntry::encrypted() const noexcept
{
    return (flags1 & PkgLayout::entry_flag_encrypted) != 0u;
}

bool FihHeader::is_official() const noexcept
{
    return signed_byte == 0x80u;
}

const char* to_string(PackageType type) noexcept
{
    switch (type) {
    case PackageType::meta:
        return "Meta";
    case PackageType::full_retail:
        return "FullRetail";
    case PackageType::full_debug:
        return "FullDebug";
    }
    return "Unknown";
}

const char* to_string(EntryId id) noexcept
{
    switch (id) {
    case EntryId::unknown:
        return "Unknown";
    case EntryId::digests:
        return "Digests";
    case EntryId::entry_keys:
        return "EntryKeys";
    case EntryId::image_key:
        return "ImageKey";
    case EntryId::general_digests:
        return "GeneralDigests";
    case EntryId::metas:
        return "Metas";
    case EntryId::entry_names:
        return "EntryNames";
    case EntryId::license_dat:
        return "LicenseDat";
    case EntryId::license_info:
        return "LicenseInfo";
    case EntryId::param_json:
        return "ParamJson";
    case EntryId::param_sfo:
        return "ParamSfo";
    case EntryId::playgo_chunk_dat:
        return "PlaygoChunkDat";
    case EntryId::playgo_chunk_sha:
        return "PlaygoChunkSha";
    case EntryId::playgo_manifest_xml:
        return "PlaygoManifestXml";
    case EntryId::icon0_png:
        return "Icon0Png";
    case EntryId::pic0_png:
        return "Pic0Png";
    case EntryId::snd0_at9:
        return "Snd0At9";
    case EntryId::icon0_dds:
        return "Icon0Dds";
    case EntryId::pic0_dds:
        return "Pic0Dds";
    case EntryId::pic1_dds:
        return "Pic1Dds";
    case EntryId::pic2_dds:
        return "Pic2Dds";
    }
    return "Unknown";
}

EntryId entry_id_from_raw(std::uint32_t raw) noexcept
{
    switch (raw) {
    case static_cast<std::uint32_t>(EntryId::digests):
        return EntryId::digests;
    case static_cast<std::uint32_t>(EntryId::entry_keys):
        return EntryId::entry_keys;
    case static_cast<std::uint32_t>(EntryId::image_key):
        return EntryId::image_key;
    case static_cast<std::uint32_t>(EntryId::general_digests):
        return EntryId::general_digests;
    case static_cast<std::uint32_t>(EntryId::metas):
        return EntryId::metas;
    case static_cast<std::uint32_t>(EntryId::entry_names):
        return EntryId::entry_names;
    case static_cast<std::uint32_t>(EntryId::license_dat):
        return EntryId::license_dat;
    case static_cast<std::uint32_t>(EntryId::license_info):
        return EntryId::license_info;
    case static_cast<std::uint32_t>(EntryId::param_json):
        return EntryId::param_json;
    case static_cast<std::uint32_t>(EntryId::param_sfo):
        return EntryId::param_sfo;
    case static_cast<std::uint32_t>(EntryId::playgo_chunk_dat):
        return EntryId::playgo_chunk_dat;
    case static_cast<std::uint32_t>(EntryId::playgo_chunk_sha):
        return EntryId::playgo_chunk_sha;
    case static_cast<std::uint32_t>(EntryId::playgo_manifest_xml):
        return EntryId::playgo_manifest_xml;
    case static_cast<std::uint32_t>(EntryId::icon0_png):
        return EntryId::icon0_png;
    case static_cast<std::uint32_t>(EntryId::pic0_png):
        return EntryId::pic0_png;
    case static_cast<std::uint32_t>(EntryId::snd0_at9):
        return EntryId::snd0_at9;
    case static_cast<std::uint32_t>(EntryId::icon0_dds):
        return EntryId::icon0_dds;
    case static_cast<std::uint32_t>(EntryId::pic0_dds):
        return EntryId::pic0_dds;
    case static_cast<std::uint32_t>(EntryId::pic1_dds):
        return EntryId::pic1_dds;
    case static_cast<std::uint32_t>(EntryId::pic2_dds):
        return EntryId::pic2_dds;
    default:
        return EntryId::unknown;
    }
}

std::optional<PackageType> detect_type(std::istream& stream)
{
    if (stream_length(stream) < 6) {
        return std::nullopt;
    }

    std::array<std::byte, 4> magic{};
    seek_abs(stream, 0);
    read_exact(stream, magic.data(), magic.size());

    if (starts_with(magic, PkgLayout::cnt_magic)) {
        return PackageType::meta;
    }

    if (starts_with(magic, PkgLayout::fih_magic)) {
        std::array<std::byte, 1> signed_byte{};
        seek_abs(stream, PkgLayout::fih_signed_byte_offset);
        read_exact(stream, signed_byte.data(), signed_byte.size());
        if (signed_byte[0] == std::byte{0x80}) {
            return PackageType::full_retail;
        }
        if (signed_byte[0] == std::byte{0x00}) {
            return PackageType::full_debug;
        }
    }

    return std::nullopt;
}

std::optional<PackageType> detect_type(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open PS5 PKG file for reading: " + path.string());
    }
    return detect_type(file);
}

Pkg read_pkg(std::istream& stream)
{
    auto type = detect_type(stream);
    if (!type) {
        throw std::runtime_error("Not a recognisable PS5 PKG (unknown magic).");
    }

    if (*type == PackageType::meta) {
        PkgHeader header = read_header(stream, 0);
        auto entries = read_entry_table(stream, header, 0);
        resolve_names(stream, entries, 0);
        return Pkg{*type, std::move(header), std::move(entries), std::nullopt};
    }

    FihHeader fih = read_fih_header(stream);
    const std::uint64_t length = stream_length(stream);
    if (fih.embedded_cnt_offset == 0 ||
        fih.embedded_cnt_offset + PkgLayout::header_size > length) {
        return Pkg{*type, std::nullopt, {}, std::move(fih)};
    }

    PkgHeader header = read_header(stream, fih.embedded_cnt_offset);
    auto entries = read_entry_table(stream, header, fih.embedded_cnt_offset);
    resolve_names(stream, entries, fih.embedded_cnt_offset);
    return Pkg{*type, std::move(header), std::move(entries), std::move(fih)};
}

Pkg read_pkg(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open PS5 PKG file for reading: " + path.string());
    }
    return read_pkg(file);
}

std::vector<std::byte> write_cnt(const PkgWriterOptions& options)
{
    if (options.content_id.empty() || options.content_id.size() > PkgLayout::content_id_size || options.passcode.size() != 32) {
        throw std::invalid_argument("Invalid content id or passcode");
    }
    std::vector<PkgWriterEntry> entries;
    auto key_modulus = read_key_file("passcode.bin");
    auto mount_modulus = read_key_file("mount_image.bin");
    if (key_modulus.size() != 7 * 384 || mount_modulus.size() != 384) throw std::runtime_error("Invalid PS5 RSA key resource size");

    std::array<std::byte, 48> padded_id{};
    std::transform(options.content_id.begin(), options.content_id.end(), padded_id.begin(), [](char c) { return static_cast<std::byte>(static_cast<unsigned char>(c)); });
    std::vector<std::byte> entry_keys(2912);
    const auto seed_digest = sha3_256(padded_id);
    std::copy(seed_digest.begin(), seed_digest.end(), entry_keys.begin());
    for (unsigned i = 0; i < 7; ++i) {
        auto key = compute_package_key(options.content_id, options.passcode, i, PackageKeyDigest::sha3_256);
        auto digest = sha3_256(key);
        for (std::size_t j = 0; j < 32; ++j) digest[j] ^= key[j];
        std::copy(digest.begin(), digest.end(), entry_keys.begin() + 32 + i * 32);
        const auto plaintext = i == 0 ? std::span<const std::byte>(reinterpret_cast<const std::byte*>(options.passcode.data()), 32) : std::span<const std::byte>(key);
        const auto wrapped = rsa_pkcs1_encrypt(std::span<const std::byte>(key_modulus).subspan(i * 384, 384), plaintext);
        std::copy(wrapped.begin(), wrapped.end(), entry_keys.begin() + 256 + i * 384);
    }
    const auto ekpfs = derive_ekpfs(options.content_id, options.passcode);
    const auto wrapped_image_key = rsa_pkcs1_encrypt(mount_modulus, ekpfs);
    std::vector<std::byte> image_key(2048);
    for (std::size_t i = 0; i < image_key.size(); i += wrapped_image_key.size()) std::copy_n(wrapped_image_key.begin(), std::min(wrapped_image_key.size(), image_key.size() - i), image_key.begin() + static_cast<std::ptrdiff_t>(i));
    auto mandatory = reverse_digest_chunks(options.pfs_image_digests);
    if (mandatory.empty()) mandatory.assign(64, std::byte{});

    entries.push_back(PkgWriterEntry{0x10, ".entry_keys", std::move(entry_keys), 0x60000000u, 0});
    entries.push_back(PkgWriterEntry{0x20, ".image_key", std::move(image_key), 0x60000000u, 0});
    entries.push_back(PkgWriterEntry{0x80, ".general_digests", std::vector<std::byte>(480), 0x60000000u, 0});
    entries.push_back(PkgWriterEntry{0x100, ".metas", {}, 0x60000000u, 0});
    entries.push_back(PkgWriterEntry{0x1, ".digests", {}, 0x40000000u, 0});
    entries.push_back(PkgWriterEntry{0x200, ".entry_names", {}, 0x40000000u, 0});
    bool mandatory_inserted = false;
    for (const auto& e : options.entries) {
        if (e.id == 0x10 || e.id == 0x20 || e.id == 0x80 || e.id == 0x100 || e.id == 0x1 || e.id == 0x200) {
            continue;
        }
        // The caller may provide a placeholder to control the body-order
        // position of imagedigs.dat.  SharpProspero stages that entry before
        // playgo/media entries, while the payload itself is finalized from
        // the outer-PFS image digest table here.
        if (e.id == 1034) {
            if (!mandatory_inserted) {
                entries.push_back(PkgWriterEntry{1034, {}, mandatory, 0x08000000u, 0});
                mandatory_inserted = true;
            }
            continue;
        }
        entries.push_back(e);
    }
    if (!mandatory_inserted) {
        entries.push_back(PkgWriterEntry{1034, {}, std::move(mandatory), 0x08000000u, 0});
    }
    const auto count = static_cast<std::uint32_t>(entries.size());
    for (auto& e : entries) if (e.id == 0x100 || e.id == 0x1) e.data.resize(static_cast<std::size_t>(count) * 32u);

    std::vector<std::size_t> name_order(entries.size());
    std::iota(name_order.begin(), name_order.end(), 0);
    std::sort(name_order.begin(), name_order.end(), [&](std::size_t a, std::size_t b) { return entries[a].name < entries[b].name; });
    std::vector<std::byte> name_table{std::byte{0}};
    std::vector<std::uint32_t> name_offsets(entries.size());
    for (const auto index : name_order) if (!entries[index].name.empty()) {
        name_offsets[index] = static_cast<std::uint32_t>(name_table.size());
        for (const char c : entries[index].name) name_table.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
        name_table.push_back(std::byte{0});
    }
    entries[5].data = std::move(name_table);

    const std::uint64_t body_offset = options.body_offset ? options.body_offset : 0x2000;
    std::vector<std::uint64_t> offsets(count);
    std::uint64_t cursor = body_offset;
    for (std::uint32_t i = 0; i < count; ++i) { cursor = (cursor + 15u) & ~std::uint64_t{15}; offsets[i] = cursor; cursor += entries[i].data.size(); }
    const std::uint64_t body_size = align_up(static_cast<std::uint32_t>(cursor - body_offset), 0x10000u);
    const std::uint64_t pfs_offset = options.pfs_image_offset ? options.pfs_image_offset : body_offset + body_size;
    if (pfs_offset < body_offset + body_size) throw std::invalid_argument("PFS offset precedes CNT body");
    std::vector<std::byte> image(static_cast<std::size_t>(pfs_offset));
    std::copy(PkgLayout::cnt_magic.begin(), PkgLayout::cnt_magic.end(), image.begin());
    write_be32(image.data() + 0x04, options.flags ? options.flags : 0x00020001u);
    write_be32(image.data() + 0x08, 0x80000000u); write_be32(image.data() + 0x0C, 12u);
    write_be32(image.data() + 0x10, count); write_be16(image.data() + 0x14, options.sc_entry_count ? options.sc_entry_count : 6);
    write_be16(image.data() + 0x16, static_cast<std::uint16_t>(count));
    write_be64(image.data() + 0x20, body_offset); write_be64(image.data() + 0x28, body_size);
    write_ascii(image, 0x40, options.content_id); write_ascii(image, 0x200, options.content_id);
    write_be32(image.data() + 0x70, options.drm_type); write_be32(image.data() + 0x74, options.content_type);
    write_be32(image.data() + 0x78, options.content_flags); write_be32(image.data() + 0x7c, static_cast<std::uint32_t>(pfs_offset));
    write_be32(image.data() + 0x80, 0x20200722u); write_be32(image.data() + 0x84, 0x01fe52e9u);
    write_be32(image.data() + 0x400, 1u); write_be32(image.data() + 0x404, 1u); write_be64(image.data() + 0x408, options.pfs_flags);
    write_be64(image.data() + 0x410, pfs_offset); write_be64(image.data() + 0x418, options.pfs_image_size);
    const auto package_size = options.package_size ? options.package_size : 0x10000ull + options.pfs_image_size + pfs_offset;
    write_be64(image.data() + 0x428, package_size);
    write_be64(image.data() + 0x430, package_size);
    write_be32(image.data() + 0x438, options.pfs_signed_size); write_be32(image.data() + 0x43c, options.pfs_cache_size);
    std::copy(options.pfs_image_digest.begin(), options.pfs_image_digest.end(), image.begin() + 0x440);
    std::copy(options.pfs_signed_digest.begin(), options.pfs_signed_digest.end(), image.begin() + 0x460);
    std::copy(options.image_seed.begin(), options.image_seed.end(), image.begin() + 0x4a0);
    write_be64(image.data() + 0x4b0, 0x10000ull + options.pfs_image_size); write_be64(image.data() + 0x4b8, pfs_offset);

    const auto find_index = [&](std::uint32_t id) { return static_cast<std::size_t>(std::find_if(entries.begin(), entries.end(), [=](const auto& e) { return e.id == id; }) - entries.begin()); };
    const auto meta_i = find_index(0x100), dig_i = find_index(0x1), image_i = find_index(0x20), general_i = find_index(0x80), mandatory_i = find_index(1034);
    std::vector<std::size_t> sorted_indices(count); std::iota(sorted_indices.begin(), sorted_indices.end(), 0);
    std::sort(sorted_indices.begin(), sorted_indices.end(), [&](std::size_t a, std::size_t b) { return entries[a].id < entries[b].id; });
    write_be32(image.data() + 0x18, static_cast<std::uint32_t>(offsets[meta_i]));
    std::uint32_t main_size = 0; for (const auto id : {0x10u, 0x20u, 0x80u, 0x100u, 0x1u}) main_size += static_cast<std::uint32_t>(entries[find_index(id)].data.size());
    write_be32(image.data() + 0x1c, main_size); write_be64(image.data() + 0x30, offsets[mandatory_i]);

    std::array<std::byte, 56> descriptor{}; std::copy_n(reinterpret_cast<const std::byte*>(options.content_id.data()), std::min<std::size_t>(36, options.content_id.size()), descriptor.begin());
    write_be32(descriptor.data() + 48, options.drm_type); write_be32(descriptor.data() + 52, options.content_type);
    std::array<std::byte, 32> zero_digest{};
    const auto content_digest = compute_content_digest(descriptor, options.pfs_image_digest, zero_digest, options.content_type != 34);
    auto& general = entries[general_i].data;
    write_be16(general.data(), 53846); write_be16(general.data() + 2, 258);
    const auto header_digest = compute_header_digest(std::span<const std::byte>(image).first(64), force_fih_relative_image_offset(std::span<const std::byte>(image).subspan(0x400, 128)));
    std::copy(content_digest.begin(), content_digest.end(), general.begin() + 0x20);
    std::copy(options.pfs_image_digest.begin(), options.pfs_image_digest.end(), general.begin() + 0x40);
    std::copy(header_digest.begin(), header_digest.end(), general.begin() + 0x60);
    const auto param_it = std::find_if(entries.begin(), entries.end(), [](const auto& e) { return e.id == 0x2000; });
    if (param_it != entries.end()) {
        const auto param_digest = sha3_256(param_it->data);
        std::copy(param_digest.begin(), param_digest.end(), general.begin() + 0xC0);
    }

    // GeneralDigests uses the fixed 14-slot order from SharpProspero.  The
    // first 32 bytes are the header, followed by Content, Game, Header,
    // System, MajorParam, Param, PlayGo, Trophy, Manual, Keymap, Origin,
    // Target, OriginGame and TargetGame slots.
    const auto set_general_digest = [&](std::size_t slot, std::span<const std::byte> digest) {
        if (digest.size() >= 32 && 0x20u + slot * 32u + 32u <= general.size()) {
            std::copy_n(digest.begin(), 32, general.begin() + static_cast<std::ptrdiff_t>(0x20u + slot * 32u));
        }
    };
    // Additional-content-no-data packages do not carry GameDigest or
    // TargetDigest in SharpProspero's GeneralDigests mask.
    const bool include_game_target = options.content_type != 34u;
    if (include_game_target) {
        set_general_digest(1, options.pfs_image_digest); // GameDigest
    }
    set_general_digest(2, header_digest);            // HeaderDigest
    if (param_it != entries.end()) {
        const auto param_digest = sha3_256(param_it->data);
        set_general_digest(5, param_digest); // ParamDigest
    }
    if (include_game_target) {
        set_general_digest(11, options.pfs_image_digest); // TargetDigest
    }

    std::uint32_t general_mask = 0x00000000u;
    general_mask |= 0x00000002u; // ContentDigest
    if (include_game_target) general_mask |= 0x00000004u; // GameDigest
    general_mask |= 0x00000008u; // HeaderDigest
    general_mask |= 0x00000040u; // ParamDigest
    if (include_game_target) general_mask |= 0x00001000u; // TargetDigest
    const auto has_id = [&](std::uint32_t id) {
        return std::any_of(entries.begin(), entries.end(), [=](const auto& entry) { return entry.id == id; });
    };
    const auto concat_entry_digest = [&](std::span<const std::uint32_t> ids) {
        std::vector<std::byte> concatenated;
        for (const auto id : ids) {
            const auto it = std::find_if(entries.begin(), entries.end(), [=](const auto& entry) {
                return entry.id == id;
            });
            if (it == entries.end()) {
                continue;
            }
            const auto digest = sha3_256(it->data);
            concatenated.insert(concatenated.end(), digest.begin(), digest.end());
        }
        return sha3_256(concatenated);
    };
    if (has_id(4097) || has_id(8208) || has_id(8209)) {
        general_mask |= 0x00000080u; // PlaygoDigest
        constexpr std::array<std::uint32_t, 3> playgo_ids{4097, 8208, 8209};
        set_general_digest(6, concat_entry_digest(playgo_ids));
    }
    constexpr std::array<std::uint32_t, 10> system_ids{
        4102, 4109, 4608, 4640, 4672, 4736, 4768, 4800, 8256, 8288};
    if (std::any_of(system_ids.begin(), system_ids.end(), has_id)) {
        general_mask |= 0x00000010u; // SystemDigest
        set_general_digest(3, concat_entry_digest(system_ids));
    }
    write_be32(general.data() + 0x1c, general_mask);

    std::vector<std::byte> digests(static_cast<std::size_t>(count) * 32u);
    for (std::size_t slot = 0; slot < sorted_indices.size(); ++slot) {
        const auto index = sorted_indices[slot];
        const auto record = offsets[meta_i] + slot * 32u;
        const auto size = static_cast<std::uint32_t>(entries[index].data.size());
        write_be32(image.data() + record, entries[index].id); write_be32(image.data() + record + 4, name_offsets[index]);
        write_be32(image.data() + record + 8, entries[index].flags1); write_be32(image.data() + record + 12, entries[index].flags2);
        write_be32(image.data() + record + 16, static_cast<std::uint32_t>(offsets[index])); write_be32(image.data() + record + 20, size);
    }
    for (std::size_t slot = 0; slot < sorted_indices.size(); ++slot) {
        const auto index = sorted_indices[slot];
        if (entries[index].id == 0x1) continue;
        const auto payload = entries[index].id == 0x100
            ? std::span<const std::byte>(image).subspan(offsets[index], count * 32u)
            : std::span<const std::byte>(entries[index].data);
        const auto digest = sha3_256(payload);
        std::copy(digest.begin(), digest.end(), digests.begin() + static_cast<std::ptrdiff_t>(slot * 32));
    }
    for (const auto index : sorted_indices) if (entries[index].id != 0x100 && entries[index].id != 0x1 && !entries[index].data.empty()) std::copy(entries[index].data.begin(), entries[index].data.end(), image.begin() + static_cast<std::ptrdiff_t>(offsets[index]));
    std::copy(digests.begin(), digests.end(), image.begin() + static_cast<std::ptrdiff_t>(offsets[dig_i]));
    const auto body_digest = compute_body_digest(std::span<const std::byte>(image).subspan(body_offset, body_size));
    const auto digest_table_hash = sha3_256(digests);
    auto concat = [&](std::initializer_list<std::uint32_t> ids, std::size_t meta_bytes) {
        std::vector<std::byte> data;
        for (const auto id : ids) { const auto index = find_index(id); const auto size = id == 0x100 ? meta_bytes : entries[index].data.size(); data.insert(data.end(), image.begin() + static_cast<std::ptrdiff_t>(offsets[index]), image.begin() + static_cast<std::ptrdiff_t>(offsets[index] + size)); }
        return sha3_256(data);
    };
    const auto sc1 = concat({0x10, 0x20, 0x80, 0x100, 0x1}, count * 32u);
    const auto sc2 = concat({0x10, 0x20, 0x80, 0x100}, static_cast<std::size_t>(options.sc_entry_count ? options.sc_entry_count : 6) * 32u);
    std::copy(sc1.begin(), sc1.end(), image.begin() + 0x100); std::copy(sc2.begin(), sc2.end(), image.begin() + 0x120); std::copy(digest_table_hash.begin(), digest_table_hash.end(), image.begin() + 0x140); std::copy(body_digest.begin(), body_digest.end(), image.begin() + 0x160);
    write_be32(image.data() + 0x510, static_cast<std::uint32_t>(offsets[image_i])); write_be32(image.data() + 0x514, static_cast<std::uint32_t>(entries[image_i].data.size()));
    write_be32(image.data() + 0x518, static_cast<std::uint32_t>(offsets[mandatory_i])); write_be32(image.data() + 0x51c, static_cast<std::uint32_t>(entries[mandatory_i].data.size()));
    auto desc_digest = sha3_256(std::span<const std::byte>(entries[image_i].data)); auto mandatory_digest = sha3_256(std::span<const std::byte>(entries[mandatory_i].data));
    std::copy(desc_digest.begin(), desc_digest.end(), image.begin() + 0x520); std::copy(mandatory_digest.begin(), mandatory_digest.end(), image.begin() + 0x540);
    if (image.size() >= 0x1000) {
        // Sharp seals the header against an FIH-relative PFS offset.  The
        // actual CNT keeps its absolute offset at 0x410, while the digest
        // preimage (and the subsequent signature preimage) uses 0x10000.
        auto seal = std::vector<std::byte>(image.begin(), image.begin() + 0x1000);
        write_be64(seal.data() + 0x410, 0x10000);
        const auto package_digest = compute_package_digest(seal);
        std::copy(package_digest.begin(), package_digest.end(), image.begin() + 0xfe0);
        std::copy(package_digest.begin(), package_digest.end(), seal.begin() + 0xfe0);
        const auto signature_digest = sha3_256(std::span<const std::byte>(seal));
        const auto signature = rsa_metadata_encrypt(signature_digest);
        std::copy(signature.begin(), signature.end(), image.begin() + 0x1000);
    }
    return image;
}

void write_cnt_file(const PkgWriterOptions& options, const std::filesystem::path& path)
{
    const auto image = write_cnt(options);
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Could not open CNT output path for writing: " + path.string());
    }
    file.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    if (!file) {
        throw std::runtime_error("Failed to write CNT output path: " + path.string());
    }
}

} // namespace prosperopkg
