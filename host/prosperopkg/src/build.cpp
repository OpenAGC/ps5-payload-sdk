// LibProsperoPkg - A library for building and inspecting PS5 packages.
// C++ port/rewrite Copyright (C) 2026 seregonwar.
// Original C# LibProsperoPkg by SvenGDK.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/build.hpp>

#include <prosperopkg/aes_xts.hpp>
#include <prosperopkg/content_id.hpp>
#include <prosperopkg/crc32c.hpp>
#include <prosperopkg/hash.hpp>
#include <prosperopkg/pfsc.hpp>
#include <prosperopkg/pfs_image.hpp>
#include <prosperopkg/pfs_keys.hpp>
#include <prosperopkg/pfs_layout.hpp>
#include <prosperopkg/naps.hpp>
#include <prosperopkg/outer_pfs.hpp>
#include <prosperopkg/pkg.hpp>
#include <prosperopkg/image_digests.hpp>
#include <prosperopkg/si.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace prosperopkg {
namespace {

constexpr std::size_t pfs_block_size = 0x10000;
constexpr std::size_t pfs_header_size = 0x10000;
constexpr std::uint64_t pfs_header_version_ps5 = 2;
constexpr std::uint64_t pfs_header_magic = 20130315;
constexpr std::size_t pfs_mode_offset = 0x1C;
constexpr std::size_t pfs_seed_offset = 0x370;
constexpr std::size_t pfs_unknown_index_offset = 0x36C;
constexpr std::uint16_t pfs_mode_unknown_always_set = 0x8;
constexpr std::uint16_t pfs_mode_encrypted = 0x4;
// SharpProspero writes FlagsPs5 as the big-endian value 131073 (0x00020001).
constexpr std::uint32_t cnt_flags_ps5 = 0x00020001u;
constexpr std::uint32_t cnt_drm_type_ps5 = 0x10u;
constexpr std::uint32_t content_type_game = 0x20u;
constexpr std::uint32_t content_type_additional_data = 0x21u;
constexpr std::uint32_t content_type_additional_no_data = 0x22u;
constexpr std::uint32_t entry_id_native_inner_image = 0x3000u;
constexpr std::uint32_t entry_id_native_build_manifest = 0x3001u;
struct SourceFile {
    std::filesystem::path full_path;
    std::string relative_path;
    std::uint64_t size = 0;
    std::uint32_t crc = 0;
};

[[nodiscard]] std::vector<std::byte> read_file_bytes(const std::filesystem::path& path);

[[nodiscard]] std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) noexcept
{
    return ((value + alignment - 1u) / alignment) * alignment;
}

[[nodiscard]] std::uint64_t read_be64(std::span<const std::byte> data, std::size_t offset)
{
    if (offset + 8 > data.size()) return 0;
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8u) | static_cast<std::uint8_t>(data[offset + i]);
    return value;
}

void write_be64(std::span<std::byte> data, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 > data.size()) {
        throw std::out_of_range("big-endian write exceeds buffer");
    }
    for (unsigned i = 0; i < 8; ++i) {
        data[offset + i] = static_cast<std::byte>(value >> ((7u - i) * 8u));
    }
}

void ensure_parent(const std::filesystem::path& path)
{
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }
}

[[nodiscard]] bool excluded_source_name(std::string_view name)
{
    return name == "disc_info.dat" ||
           name == "pfs-version.dat" ||
           name == "ext_info.dat";
}

[[nodiscard]] bool excluded_source_suffix(std::string_view name)
{
    const auto has_suffix = [&](std::string_view suffix) {
        return name.size() >= suffix.size() &&
               std::equal(suffix.rbegin(), suffix.rend(), name.rbegin(), [](char lhs, char rhs) {
                   const auto lower = [](char ch) {
                       return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
                   };
                   return lower(lhs) == lower(rhs);
               });
    };
    return has_suffix(".gp4") || has_suffix(".gp5") || has_suffix(".esbak") || has_suffix(".dds");
}

// These files are represented as CNT entries in a package. SharpProspero's
// PS5 inner assembler omits them from the nested data-first PFS, while the
// package writer still emits param.json (and the other metadata) separately.
[[nodiscard]] bool excluded_from_package_inner(std::string_view relative_path)
{
    constexpr std::string_view prefix = "sce_sys/";
    if (relative_path.size() <= prefix.size() ||
        relative_path.substr(0, prefix.size()) != prefix) {
        return false;
    }

    constexpr std::array<std::string_view, 39> cnt_names{
        "param.json", ".digests", ".entry_keys", ".image_key", ".general_digests",
        ".metas", ".entry_names", "license.dat", "license.info", "nptitle.dat",
        "npbind.dat", "selfinfo.dat", "imageinfo.dat", "target-deltainfo.dat",
        "origin-deltainfo.dat", "psreserved.dat", "param.sfo", "playgo-chunk.dat",
        "playgo-chunk.sha", "playgo-manifest.xml", "pronunciation.sig", "pronunciation.xml",
        "pic1.png", "pic2.png", "pubtoolinfo.dat", "shareparam.json", "shareoverlayimage.png",
        "save_data.png", "shareprivacyguardimage.png", "icon0.png", "pic0.png", "snd0.at9",
        "changeinfo/changeinfo.xml", "icon0.dds", "pic0.dds", "pic1.dds",
        "app/playgo-chunk.dat", "app/playgo-chunk.sha", "app/playgo-manifest.xml"};
    const auto name = relative_path.substr(prefix.size());
    if (std::find(cnt_names.begin(), cnt_names.end(), name) != cnt_names.end()) {
        return true;
    }

    const auto has_two_digit_suffix = [](std::string_view value,
                                          std::string_view prefix_name,
                                          std::string_view suffix,
                                          unsigned max_value) {
        if (value.size() != prefix_name.size() + 2u + suffix.size() ||
            value.substr(0, prefix_name.size()) != prefix_name ||
            value.substr(value.size() - suffix.size()) != suffix) {
            return false;
        }
        const auto tens = value[prefix_name.size()];
        const auto ones = value[prefix_name.size() + 1u];
        if (tens < '0' || tens > '9' || ones < '0' || ones > '9') {
            return false;
        }
        return static_cast<unsigned>(tens - '0') * 10u + static_cast<unsigned>(ones - '0') <= max_value;
    };
    if (has_two_digit_suffix(name, "icon0_", ".png", 30u) ||
        has_two_digit_suffix(name, "icon0_", ".dds", 30u) ||
        has_two_digit_suffix(name, "pic1_", ".png", 30u) ||
        has_two_digit_suffix(name, "pic1_", ".dds", 30u) ||
        has_two_digit_suffix(name, "changeinfo/changeinfo_", ".xml", 30u) ||
        has_two_digit_suffix(name, "trophy/trophy", ".trp", 99u)) {
        return true;
    }

    // keymap_rp contains one-digit and two-digit numbered PNG entries.
    if (name.size() >= 12u && name.substr(0, 10u) == "keymap_rp/") {
        const auto rest = name.substr(10u);
        if (rest.size() == 7u && rest[0] >= '0' && rest[0] <= '9' &&
            rest[1] >= '0' && rest[1] <= '9' && rest[2] >= '0' && rest[2] <= '9' &&
            rest.substr(3) == ".png") {
            return true;
        }
        if (rest.size() == 11u && rest[0] >= '0' && rest[0] <= '9' &&
            rest[1] >= '0' && rest[1] <= '9' && rest[2] == '/' &&
            rest[3] == '0' && rest[4] >= '0' && rest[4] <= '9' && rest[5] >= '0' &&
            rest[5] <= '9' && rest.substr(6) == ".png") {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string relative_generic_string(
    const std::filesystem::path& full_path,
    const std::filesystem::path& root)
{
    return std::filesystem::relative(full_path, root).generic_string();
}

[[nodiscard]] std::uint32_t file_crc32c(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open source file: " + path.string());
    }

    std::array<std::byte, 64 * 1024> buffer{};
    std::uint32_t crc = 0xFFFFFFFFu;
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto got = file.gcount();
        if (got > 0) {
            crc = crc32c_update(crc, std::span<const std::byte>(buffer.data(), static_cast<std::size_t>(got)));
        }
    }
    return ~crc;
}

[[nodiscard]] std::vector<SourceFile> enumerate_source_files(const std::filesystem::path& source_folder)
{
    if (!std::filesystem::is_directory(source_folder)) {
        throw std::invalid_argument("Source folder does not exist: " + source_folder.string());
    }

    std::vector<SourceFile> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source_folder)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const std::string name = entry.path().filename().string();
        if (excluded_source_name(name) || excluded_source_suffix(name)) {
            continue;
        }

        SourceFile file;
        file.full_path = entry.path();
        file.relative_path = relative_generic_string(entry.path(), source_folder);
        file.size = entry.file_size();
        file.crc = file_crc32c(entry.path());
        files.push_back(std::move(file));
    }

    std::sort(files.begin(), files.end(), [](const SourceFile& lhs, const SourceFile& rhs) {
        return lhs.relative_path < rhs.relative_path;
    });
    return files;
}

void append_le32(std::vector<std::byte>& out, std::uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
    }
}

void append_le64(std::vector<std::byte>& out, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
    }
}

void write_le16(std::span<std::byte> data, std::size_t offset, std::uint16_t value)
{
    data[offset] = static_cast<std::byte>(value & 0xFFu);
    data[offset + 1] = static_cast<std::byte>((value >> 8u) & 0xFFu);
}

void write_le32(std::span<std::byte> data, std::size_t offset, std::uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        data[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
    }
}

void write_le64(std::span<std::byte> data, std::size_t offset, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        data[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
    }
}

[[nodiscard]] std::array<std::byte, 16> deterministic_seed(
    std::string_view content_id,
    std::string_view passcode,
    std::span<const SourceFile> files)
{
    std::vector<std::byte> material;
    const auto add_text = [&](std::string_view text) {
        for (char ch : text) {
            material.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        material.push_back(std::byte{0});
    };
    add_text("LibProsperoPkg.NativeInnerSeed.v1");
    add_text(content_id);
    add_text(passcode);
    for (const auto& file : files) {
        add_text(file.relative_path);
        append_le64(material, file.size);
        append_le32(material, file.crc);
    }

    const auto digest = sha256(material);
    std::array<std::byte, 16> seed{};
    std::copy_n(digest.begin(), seed.size(), seed.begin());
    return seed;
}

void copy_file_to_stream(const std::filesystem::path& path, std::ostream& out)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open source file: " + path.string());
    }

    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto got = input.gcount();
        if (got > 0) {
            out.write(buffer.data(), got);
        }
    }
    if (!out) {
        throw std::runtime_error("Could not write source file payload: " + path.string());
    }
}

void write_padding(std::ostream& out, std::uint64_t count)
{
    std::array<char, 4096> zeros{};
    while (count > 0) {
        const auto chunk = static_cast<std::streamsize>(std::min<std::uint64_t>(count, zeros.size()));
        out.write(zeros.data(), chunk);
        count -= static_cast<std::uint64_t>(chunk);
    }
}

void write_inner_plain(
    const std::filesystem::path& source_folder,
    const std::filesystem::path& output_path,
    std::string_view content_id,
    std::string_view passcode,
    bool encrypted_mode)
{
    auto files = enumerate_source_files(source_folder);
    const auto seed = deterministic_seed(content_id, passcode, files);

    std::vector<InnerPfsFile> layout_files;
    layout_files.reserve(files.size());
    for (const auto& file : files) {
        layout_files.push_back(InnerPfsFile{file.relative_path, read_file_bytes(file.full_path)});
    }
    auto layout = build_standalone_pfs_layout(std::move(layout_files), 0, 0);
    auto image = std::move(layout.image);
    if (image.size() < pfs_header_size) {
        throw std::runtime_error("Standalone PFS layout did not produce a superblock.");
    }
    // SharpProspero writes the seed when transitioning a plaintext layout to
    // encrypted mode. Keeping the same deterministic seed makes the native
    // host output reproducible while retaining the exact header location.
    std::copy(seed.begin(), seed.end(), image.begin() + static_cast<std::ptrdiff_t>(pfs_seed_offset));
    write_le32(image, pfs_unknown_index_offset, 1);
    write_le16(image, pfs_mode_offset, static_cast<std::uint16_t>(
        pfs_mode_unknown_always_set | (encrypted_mode ? pfs_mode_encrypted : 0)));

    ensure_parent(output_path);
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Could not create inner image: " + output_path.string());
    }

    output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    if (!output) {
        throw std::runtime_error("Could not write inner image: " + output_path.string());
    }
}

[[nodiscard]] std::vector<std::byte> read_file_bytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file: " + path.string());
    }
    file.seekg(0, std::ios::end);
    const auto end = file.tellg();
    if (end < 0) {
        throw std::runtime_error("Could not determine file size: " + path.string());
    }
    file.seekg(0, std::ios::beg);
    std::vector<std::byte> data(static_cast<std::size_t>(end));
    if (!data.empty()) {
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (file.gcount() != static_cast<std::streamsize>(data.size())) {
            throw std::runtime_error("Could not read file: " + path.string());
        }
    }
    return data;
}

void write_file_bytes(const std::filesystem::path& path, std::span<const std::byte> data)
{
    ensure_parent(path);
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Could not create file: " + path.string());
    }
    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!file) {
        throw std::runtime_error("Could not write file: " + path.string());
    }
}

void encrypt_inner_image_in_place(
    const std::filesystem::path& path,
    std::string_view content_id,
    std::string_view passcode)
{
    auto image = read_file_bytes(path);
    if (image.size() < pfs_header_size || (image.size() % pfs_inner_xts_sector_size) != 0) {
        throw std::runtime_error("Native inner image has invalid size for encryption.");
    }

    std::array<std::byte, 16> seed{};
    std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(pfs_seed_offset), seed.size(), seed.begin());
    const auto ekpfs = compute_package_key(content_id, passcode, 1, PackageKeyDigest::sha256);
    const auto keys = derive_pfs_encryption_keys(ekpfs, seed, false);
    write_le16(image, pfs_mode_offset, pfs_mode_unknown_always_set | pfs_mode_encrypted);

    const std::size_t start_sector = pfs_block_size / pfs_inner_xts_sector_size;
    const std::size_t total_sectors = image.size() / pfs_inner_xts_sector_size;
    for (std::size_t sector = start_sector; sector < total_sectors; ++sector) {
        auto unit = std::span<std::byte>(image).subspan(
            sector * pfs_inner_xts_sector_size,
            pfs_inner_xts_sector_size);
        xts_transform_unit(unit, keys.data_key, keys.tweak_key, sector, true);
    }

    write_file_bytes(path, image);
}

[[nodiscard]] bool is_version_digits(std::string_view version, std::size_t first_width,
    std::size_t second_width, std::size_t third_width = 0)
{
    const auto expected = first_width + 1u + second_width + (third_width ? 1u + third_width : 0u);
    if (version.size() != expected || version[first_width] != '.') {
        return false;
    }
    if (third_width && version[first_width + 1u + second_width] != '.') {
        return false;
    }
    for (std::size_t i = 0; i < version.size(); ++i) {
        if (version[i] == '.') continue;
        if (version[i] < '0' || version[i] > '9') return false;
    }
    return true;
}

[[nodiscard]] std::string normalize_master_version(std::string_view version)
{
    if (is_version_digits(version, 2, 2)) return std::string(version);
    if (is_version_digits(version, 2, 3, 3)) {
        return std::string(version.substr(0, 2)) + "." + std::string(version.substr(3, 2));
    }
    return "01.00";
}

[[nodiscard]] std::string normalize_content_version(std::string_view version)
{
    if (is_version_digits(version, 2, 3, 3)) return std::string(version);
    const auto master = normalize_master_version(version);
    return master.substr(0, 2) + ".000.000";
}

[[nodiscard]] std::uint32_t content_version_high(std::string_view version)
{
    const auto normalized = normalize_content_version(version);
    const auto major = static_cast<unsigned>(normalized[0] - '0') * 10u +
        static_cast<unsigned>(normalized[1] - '0');
    return static_cast<std::uint32_t>(((major / 10u) << 4u | (major % 10u)) << 24u);
}

[[nodiscard]] std::filesystem::path package_output_path(const PackageBuildOptions& options)
{
    std::string version = normalize_master_version(options.version);
    version.erase(std::remove(version.begin(), version.end(), '.'), version.end());
    while (version.size() < 4) {
        version.insert(version.begin(), '0');
    }
    const std::string name =
        options.content_id + "-A" + version.substr(0, 4) + "-V" + version.substr(0, 4) + ".pkg";
    return options.output_folder / name;
}

[[nodiscard]] std::string fallback_title_id(const PackageBuildOptions& options)
{
    if (is_valid_title_id(options.title_id)) {
        return options.title_id;
    }
    if (options.content_id.size() >= 16) {
        return options.content_id.substr(7, 9);
    }
    return "PPSA00000";
}

[[nodiscard]] std::string minimal_param_json(const PackageBuildOptions& options)
{
    const std::string title_id = fallback_title_id(options);
    const std::string title = options.title.empty() ? title_id : options.title;
    const std::string content_version = normalize_content_version(options.version);
    const std::string master_version = normalize_master_version(options.version);
    return "{\n"
           "  \"applicationCategoryType\": 0,\n"
           "  \"contentId\": \"" + options.content_id + "\",\n"
           "  \"contentVersion\": \"" + content_version + "\",\n"
           "  \"masterVersion\": \"" + master_version + "\",\n"
           "  \"requiredSystemSoftwareVersion\": \"00.00.00.00\",\n"
           "  \"titleId\": \"" + title_id + "\",\n"
           "  \"localizedParameters\": {\n"
           "    \"defaultLanguage\": \"en-US\",\n"
           "    \"en-US\": { \"titleName\": \"" + title + "\" }\n"
           "  }\n"
           "}\n";
}

[[nodiscard]] std::vector<std::byte> bytes_from_string(std::string_view text)
{
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char ch : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return out;
}

[[nodiscard]] std::vector<std::byte> create_keystone(std::string_view passcode)
{
    // This is the PS5 debug keystone format used by SharpProspero: a fixed
    // 0x20-byte header followed by two SHA-256 HMAC blocks.  A supplied
    // sce_sys/keystone is kept verbatim; this helper is only used when it is
    // absent from the input tree.
    constexpr std::array<std::byte, 32> fingerprint_key{
        std::byte{0xFE}, std::byte{0x2F}, std::byte{0x86}, std::byte{0xDC},
        std::byte{0x4C}, std::byte{0x11}, std::byte{0x0C}, std::byte{0x93},
        std::byte{0xB1}, std::byte{0xF6}, std::byte{0x87}, std::byte{0xD2},
        std::byte{0xDA}, std::byte{0x21}, std::byte{0xB8}, std::byte{0x78},
        std::byte{0x62}, std::byte{0xFD}, std::byte{0x16}, std::byte{0xE3},
        std::byte{0x1D}, std::byte{0xC0}, std::byte{0xF0}, std::byte{0xA8},
        std::byte{0x32}, std::byte{0x10}, std::byte{0x35}, std::byte{0xFD},
        std::byte{0xDF}, std::byte{0x6C}, std::byte{0x56}, std::byte{0xB7}};
    constexpr std::array<std::byte, 32> mac_key{
        std::byte{0x4B}, std::byte{0xAC}, std::byte{0x10}, std::byte{0x05},
        std::byte{0x83}, std::byte{0xDC}, std::byte{0x7E}, std::byte{0xD2},
        std::byte{0x17}, std::byte{0x8D}, std::byte{0x0C}, std::byte{0xE1},
        std::byte{0x99}, std::byte{0xFE}, std::byte{0xE9}, std::byte{0xA2},
        std::byte{0xD7}, std::byte{0x2C}, std::byte{0x7B}, std::byte{0x7B},
        std::byte{0x0A}, std::byte{0x10}, std::byte{0xB7}, std::byte{0x2F},
        std::byte{0xE4}, std::byte{0xBE}, std::byte{0x51}, std::byte{0xD8},
        std::byte{0xBC}, std::byte{0xA1}, std::byte{0x88}, std::byte{0x28}};

    std::array<std::byte, 0x20> header{};
    const auto tag = bytes_from_string("keystone");
    std::copy(tag.begin(), tag.end(), header.begin());
    header[8] = std::byte{3}; // little-endian version 3
    header[10] = std::byte{1};

    const auto passcode_bytes = bytes_from_string(passcode);
    const auto fingerprint = hmac_sha256(fingerprint_key, passcode_bytes);
    std::vector<std::byte> first_data;
    first_data.reserve(header.size() + fingerprint.size());
    first_data.insert(first_data.end(), header.begin(), header.end());
    first_data.insert(first_data.end(), fingerprint.begin(), fingerprint.end());
    const auto final = hmac_sha256(mac_key, first_data);

    std::vector<std::byte> output;
    output.reserve(header.size() + fingerprint.size() + final.size());
    output.insert(output.end(), header.begin(), header.end());
    output.insert(output.end(), fingerprint.begin(), fingerprint.end());
    output.insert(output.end(), final.begin(), final.end());
    return output;
}

[[nodiscard]] std::vector<std::byte> load_optional_right_sprx()
{
    std::vector<std::filesystem::path> candidates;
    if (const char* configured = std::getenv("PROSPERO_PKG_RIGHT_SPRX")) {
        if (*configured != '\0') candidates.emplace_back(configured);
    }
    if (const char* sdk = std::getenv("PS5_PAYLOAD_SDK")) {
        const auto root = std::filesystem::path(sdk);
        candidates.push_back(root / "share/prosperopkg/right.sprx");
        candidates.push_back(root / "share/prosperopkg/PlayGo/Data/right.sprx");
    }
    // Source-tree fallbacks keep an uninstalled host build usable from either
    // the repository root or the host directory.
    candidates.emplace_back("host/prosperopkg/data/right.sprx");
    candidates.emplace_back("prosperopkg/data/right.sprx");
    candidates.emplace_back("/opt/ps5-payload-sdk/share/prosperopkg/right.sprx");
    candidates.emplace_back("/opt/ps5-payload-sdk/share/prosperopkg/PlayGo/Data/right.sprx");

    for (const auto& path : candidates) {
        try {
            if (!std::filesystem::is_regular_file(path)) continue;
            auto data = read_file_bytes(path);
            if (!data.empty()) return data;
        } catch (const std::exception&) {
            // An optional resource must not prevent packaging when a caller
            // supplies a complete sce_sys/about tree itself.
        }
    }
    return {};
}

// The PlayGo descriptors are generated by SharpProspero even when the input
// application does not provide PlayGo files.  Keep these byte layouts local
// so the package writer does not depend on a separate PlayGo runtime.
[[nodiscard]] std::vector<std::byte> build_playgo_chunk_dat(
    std::string_view content_id,
    std::uint64_t mchunk0_size,
    std::uint64_t mchunk1_size)
{
    std::vector<std::byte> out(416);
    const auto span = std::span<std::byte>(out);
    out[0] = std::byte{'p'}; out[1] = std::byte{'l'}; out[2] = std::byte{'g'}; out[3] = std::byte{'x'};
    write_le16(span, 4, 4096); write_le16(span, 8, 1); write_le16(span, 10, 1);
    write_le16(span, 14, 1); write_le32(span, 16, 416); write_le16(span, 22, 1);
    write_le32(span, 24, 0); out[30] = std::byte{133}; out[32] = std::byte{2}; out[36] = std::byte{1}; out[48] = std::byte{17};
    for (std::size_t i = 56; i < 64; ++i) out[i] = std::byte{0xFF};
    if (content_id.size() != 36) throw std::invalid_argument("Content ID must be exactly 36 characters.");
    for (std::size_t i = 0; i < content_id.size(); ++i) out[64 + i] = static_cast<std::byte>(static_cast<unsigned char>(content_id[i]));
    write_le32(span, 192, 256); write_le32(span, 196, 32);
    write_le32(span, 200, 288); write_le32(span, 204, 8);
    write_le32(span, 208, 304); write_le32(span, 212, 9);
    write_le32(span, 216, 320); write_le32(span, 220, 32);
    write_le32(span, 224, 352); write_le32(span, 228, 32);
    write_le32(span, 232, 384); write_le32(span, 236, 2);
    write_le32(span, 240, 400); write_le32(span, 244, 12);
    out[256] = std::byte{128}; out[258] = std::byte{3}; out[260] = std::byte{2}; out[264] = std::byte{17};
    write_le64(span, 272, std::numeric_limits<std::uint64_t>::max());
    write_le32(span, 292, 1);
    const auto chunk_name = bytes_from_string("Chunk #0");
    std::copy(chunk_name.begin(), chunk_name.end(), out.begin() + 304);
    write_le64(span, 320, 0); write_le64(span, 328, mchunk0_size); write_le64(span, 336, mchunk0_size); write_le64(span, 344, mchunk1_size);
    write_le64(span, 352, 33); out[372] = std::byte{1}; out[374] = std::byte{1};
    const auto scenario_name = bytes_from_string("Scenario #0");
    std::copy(scenario_name.begin(), scenario_name.end(), out.begin() + 400);
    return out;
}

[[nodiscard]] std::vector<std::byte> build_playgo_hash_table(std::uint32_t chunk_count)
{
    constexpr std::array<std::array<std::byte, 8>, 5> entries{{
        {{std::byte{142}, std::byte{84}, std::byte{203}, std::byte{77}, std::byte{74}, std::byte{246}, std::byte{48}, std::byte{14}}},
        {{std::byte{242}, std::byte{191}, std::byte{246}, std::byte{39}, std::byte{185}, std::byte{143}, std::byte{136}, std::byte{83}}},
        {{std::byte{203}, std::byte{220}, std::byte{198}, std::byte{62}, std::byte{236}, std::byte{179}, std::byte{196}, std::byte{174}}},
        {{std::byte{11}, std::byte{244}, std::byte{233}, std::byte{197}, std::byte{218}, std::byte{248}, std::byte{201}, std::byte{174}}},
        {{std::byte{76}, std::byte{247}, std::byte{12}, std::byte{8}, std::byte{23}, std::byte{77}, std::byte{203}, std::byte{211}}}}};
    if (chunk_count > 65536) throw std::invalid_argument("PlayGo chunk count is too large.");
    std::vector<std::byte> out(56u + static_cast<std::size_t>(chunk_count) * 8u);
    const auto span = std::span<std::byte>(out);
    write_le32(span, 0, 1); write_le32(span, 4, 0x08000000); write_le32(span, 8, 56);
    write_le32(span, 12, chunk_count * 8u); out[24] = std::byte{0x7F}; out[25] = std::byte{'F'}; out[26] = std::byte{'L'}; out[27] = std::byte{'T'};
    write_le32(span, 36, chunk_count);
    constexpr std::array<std::byte, 16> prefix{{std::byte{81}, std::byte{79}, std::byte{162}, std::byte{38}, std::byte{171}, std::byte{138}, std::byte{202}, std::byte{146}, std::byte{77}, std::byte{196}, std::byte{27}, std::byte{164}, std::byte{97}, std::byte{183}, std::byte{187}, std::byte{9}}};
    std::copy(prefix.begin(), prefix.end(), out.begin() + 40);
    for (std::uint32_t i = 0; i < chunk_count; ++i) std::copy(entries[std::min<std::size_t>(i, entries.size() - 1)].begin(), entries[std::min<std::size_t>(i, entries.size() - 1)].end(), out.begin() + 56 + static_cast<std::size_t>(i) * 8u);
    return out;
}

[[nodiscard]] std::vector<std::byte> build_playgo_ficm(std::uint32_t file_count)
{
    if (file_count > 1048576) throw std::invalid_argument("PlayGo file count is too large.");
    std::vector<std::byte> out(16u + file_count);
    const auto span = std::span<std::byte>(out);
    write_le32(span, 0, 1); write_le32(span, 8, 16); write_le32(span, 12, file_count);
    return out;
}

[[nodiscard]] std::vector<PkgWriterEntry> collect_media_entries(const std::filesystem::path& source_folder)
{
    struct Media { std::string name; std::uint32_t id; };
    const std::array<Media, 10> media{{
        {"icon0.png", 4608}, {"pic0.png", 4640}, {"pic1.png", 4102}, {"pic2.png", 8256}, {"snd0.at9", 4672}, {"save_data.png", 4109},
        {"icon0.dds", 4736}, {"pic0.dds", 4768}, {"pic1.dds", 4800}, {"pic2.dds", 8288}}};
    std::vector<PkgWriterEntry> out;
    const auto add = [&](std::string name, std::uint32_t id) {
        const auto path = source_folder / "sce_sys" / name;
        if (std::filesystem::is_regular_file(path)) {
            out.push_back(PkgWriterEntry{id, std::move(name), read_file_bytes(path), 0x08000000u, 0});
        }
    };
    for (const auto& item : media) {
        add(item.name, item.id);
    }
    const auto two_digits = [](unsigned value) {
        auto text = std::to_string(value);
        if (text.size() < 2) text.insert(text.begin(), '0');
        return text;
    };
    for (unsigned i = 0; i <= 30; ++i) {
        add("icon0_" + two_digits(i) + ".png", 4609u + i);
        add("icon0_" + two_digits(i) + ".dds", 4737u + i);
        add("pic1_" + two_digits(i) + ".png", 4673u + i);
        add("pic1_" + two_digits(i) + ".dds", 4801u + i);
        add("changeinfo/changeinfo_" + two_digits(i) + ".xml", 4705u + i);
        if (i < 10) {
            add("keymap_rp/0" + two_digits(i + 1) + ".png", 5632u + i);
            for (unsigned j = 0; j < 10; ++j) {
                add("keymap_rp/" + two_digits(i) + "/0" + two_digits(j + 1) + ".png", 5648u + 16u * i + j);
            }
        }
    }
    for (unsigned i = 0; i < 100; ++i) {
        add("trophy/trophy" + two_digits(i) + ".trp", 5120u + i);
    }
    return out;
}

[[nodiscard]] std::vector<std::byte> param_json_bytes(const PackageBuildOptions& options)
{
    const auto path = options.source_folder / "sce_sys" / "param.json";
    if (std::filesystem::is_regular_file(path)) {
        return read_file_bytes(path);
    }
    return bytes_from_string(minimal_param_json(options));
}

[[nodiscard]] std::uint32_t content_type_for(BuildMode mode) noexcept
{
    switch (mode) {
    case BuildMode::additional_content_data:
        return content_type_additional_data;
    case BuildMode::additional_content_no_data:
        return content_type_additional_no_data;
    case BuildMode::application:
    case BuildMode::homebrew:
        return content_type_game;
    }
    return content_type_game;
}

[[nodiscard]] std::string build_manifest_json(
    const PackageBuildOptions& options,
    const std::vector<std::byte>& inner_image)
{
    const auto digest = sha256(inner_image);
    auto hex = [](std::span<const std::byte> data) {
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (std::byte byte : data) {
            const auto value = static_cast<unsigned char>(byte);
            out.push_back(digits[value >> 4u]);
            out.push_back(digits[value & 0x0Fu]);
        }
        return out;
    };

    return "{\n"
           "  \"builder\": \"LibProsperoPkg C++ native\",\n"
           "  \"contentId\": \"" + options.content_id + "\",\n"
           "  \"titleId\": \"" + fallback_title_id(options) + "\",\n"
           "  \"version\": \"" + normalize_master_version(options.version) + "\",\n"
           "  \"innerImageSize\": " + std::to_string(inner_image.size()) + ",\n"
           "  \"innerImageSha256\": \"" + hex(digest) + "\"\n"
           "}\n";
}

[[nodiscard]] std::array<std::byte, PkgLayout::fih_header_region_size> build_fih_header(
    std::span<const std::byte> pfs_image,
    std::size_t superblock_index,
    std::span<const std::byte> superblock_digest,
    std::span<const std::byte> nested_image_digest = {},
    std::uint64_t nested_image_size = 0,
    std::uint64_t nested_meta_base_blocks = 0,
    std::uint32_t inner_content_inodes = 0,
    std::uint32_t app_file_count = 0,
    std::uint32_t content_version_hi = 0)
{
    const std::uint64_t pfs_offset = PkgLayout::fih_header_region_size;
    std::array<std::byte, PkgLayout::fih_header_region_size> header{};
    std::copy(PkgLayout::fih_magic.begin(), PkgLayout::fih_magic.end(), header.begin());
    header[0x04] = std::byte{1}; header[PkgLayout::fih_signed_byte_offset] = std::byte{0}; header[0x06] = std::byte{3};
    write_le32(header, 0x08, 1); write_le64(header, 0x10, pfs_offset); write_le64(header, 0x18, pfs_image.size());
    write_le64(header, 0x20, pfs_offset + superblock_index * pfs_block_size); write_le64(header, 0x28, pfs_block_size);
    write_le64(header, 0x60, 0x10000); write_le64(header, 0x68, 0x800000000000ull);
    if (nested_meta_base_blocks != 0) {
        write_le64(header, 0x50, nested_meta_base_blocks);
    }
    if (superblock_digest.size() >= 32) {
        std::copy_n(superblock_digest.begin(), 32, header.begin() + 0x30);
        std::copy_n(superblock_digest.begin(), 32, header.begin() + 0x70);
        std::copy_n(superblock_digest.begin(), 32, header.begin() + 0xD0);
    }
    const auto cnt_offset = pfs_offset + align_up(pfs_image.size(), pfs_block_size);
    write_le64(header, PkgLayout::fih_embedded_cnt_offset_field, cnt_offset);
    const auto image_blocks = static_cast<std::uint32_t>(align_up(pfs_image.size(), pfs_block_size) / pfs_block_size);
    const auto inner_blocks = superblock_index > 0 ? static_cast<std::uint32_t>(superblock_index - 1) : 0u;
    const auto metadata_blocks = image_blocks > inner_blocks ? image_blocks - inner_blocks : 0u;
    const auto content_blocks = inner_content_inodes != 0 ? inner_content_inodes : metadata_blocks;
    write_le32(header, 0x90, inner_blocks); write_le32(header, 0x94, content_blocks); write_le32(header, 0x98, content_blocks);
    if (content_version_hi != 0) write_le32(header, 0x9c, content_version_hi);
    write_le64(header, 0xA0, static_cast<std::uint64_t>(inner_blocks) * pfs_block_size);
    write_le64(header, 0xA8, nested_image_size != 0 ? nested_image_size : static_cast<std::uint64_t>(inner_blocks) * pfs_block_size);
    if (nested_image_digest.size() >= image_digest_size) {
        std::copy_n(nested_image_digest.begin(), image_digest_size, header.begin() + 0xB0);
    } else {
        const auto fallback = sha3_256(pfs_image);
        std::copy(fallback.begin(), fallback.end(), header.begin() + 0xB0);
    }
    write_le32(header, 0xF0, inner_content_inodes != 0 && app_file_count != 0 ? app_file_count : 1u); write_le32(header, 0xF8, 2);
    return header;
}

void write_fih_package(
    const std::filesystem::path& output_path,
    std::span<const std::byte> pfs_image,
    std::span<const std::byte> cnt,
    std::size_t superblock_index,
    std::span<const std::byte> superblock_digest,
    std::span<const std::byte> nested_image_digest = {},
    std::uint64_t nested_image_size = 0,
    std::uint64_t nested_meta_base_blocks = 0,
    std::uint32_t inner_content_inodes = 0,
    std::uint32_t app_file_count = 0,
    std::uint32_t content_version_hi = 0,
    std::span<const std::byte> si = {})
{
    const std::uint64_t pfs_offset = PkgLayout::fih_header_region_size;
    const std::uint64_t cnt_offset = pfs_offset + align_up(pfs_image.size(), pfs_block_size);
    const auto header = build_fih_header(pfs_image, superblock_index, superblock_digest,
        nested_image_digest, nested_image_size, nested_meta_base_blocks,
        inner_content_inodes, app_file_count, content_version_hi);

    ensure_parent(output_path);
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Could not create FIH package: " + output_path.string());
    }
    out.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (!pfs_image.empty()) {
        out.write(reinterpret_cast<const char*>(pfs_image.data()), static_cast<std::streamsize>(pfs_image.size()));
    }
    const std::uint64_t after_pfs = pfs_offset + pfs_image.size();
    if (cnt_offset > after_pfs) {
        write_padding(out, cnt_offset - after_pfs);
    }
    if (!cnt.empty()) {
        out.write(reinterpret_cast<const char*>(cnt.data()), static_cast<std::streamsize>(cnt.size()));
    }
    if (!si.empty()) {
        out.write(reinterpret_cast<const char*>(si.data()), static_cast<std::streamsize>(si.size()));
    }
    if (!out) {
        throw std::runtime_error("Could not write FIH package: " + output_path.string());
    }
}

[[nodiscard]] std::filesystem::path temp_path_near(
    const std::filesystem::path& directory,
    std::string_view suffix)
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return directory / (".libprosperopkg-" + std::to_string(ticks) + std::string(suffix));
}

void validate_common(std::string_view content_id, std::string_view passcode)
{
    if (!is_valid_content_id(content_id)) {
        throw std::invalid_argument("Content ID is not in the format XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ.");
    }
    if (passcode.size() != 32) {
        throw std::invalid_argument("Passcode must be exactly 32 characters.");
    }
}

} // namespace

std::filesystem::path build_inner_image(const InnerImageBuildOptions& options)
{
    validate_common(options.content_id, options.passcode);
    if (options.output_path.empty()) {
        throw std::invalid_argument("Inner image output path is empty.");
    }

    const bool encrypted = options.form == InnerImageForm::encrypted;
    write_inner_plain(options.source_folder, options.output_path, options.content_id, options.passcode, encrypted);

    if (encrypted) {
        encrypt_inner_image_in_place(options.output_path, options.content_id, options.passcode);
    } else if (options.form == InnerImageForm::compressed) {
        const auto raw_path = options.output_path;
        const auto pfsc_path = raw_path.string() + ".pfsc.tmp";
        pack_pfsc_zlib(raw_path, pfsc_path, 9, static_cast<std::uint32_t>(pfs_block_size));
        std::filesystem::remove(raw_path);
        std::filesystem::rename(pfsc_path, raw_path);
    } else if (options.form == InnerImageForm::kraken_compressed) {
        const auto raw_path = options.output_path;
        const auto pfsc_path = raw_path.string() + ".pfsv3.tmp";
        pack_pfsc_pfs_v3_compressed(raw_path, pfsc_path, 7, 0x40000);
        std::filesystem::remove(raw_path);
        std::filesystem::rename(pfsc_path, raw_path);
    } else if (options.form != InnerImageForm::plaintext) {
        throw std::invalid_argument("Unknown inner image form.");
    }

    return options.output_path;
}

std::filesystem::path build_package(const PackageBuildOptions& options)
{
    validate_common(options.content_id, options.passcode);
    if (!std::filesystem::is_directory(options.source_folder)) {
        throw std::invalid_argument("Source folder does not exist: " + options.source_folder.string());
    }
    if (options.output_folder.empty()) {
        throw std::invalid_argument("Output folder is empty.");
    }

    std::filesystem::create_directories(options.output_folder);
    const auto output_path = package_output_path(options);
    const auto inner_tmp = temp_path_near(options.output_folder, ".pfs.tmp");

    InnerImageForm form = InnerImageForm::encrypted;
    if (options.output_format == BuildOutputFormat::debug_image) {
        // SharpProspero stores the data-first inner PFS as a file inside the
        // encrypted outer PFS. Compression is represented by its inode
        // metadata, not by encrypting the standalone image first.
        form = InnerImageForm::plaintext;
    } else if (options.inner_compression == InnerCompression::zlib) {
        form = InnerImageForm::compressed;
    } else if (options.inner_compression == InnerCompression::kraken) {
        form = InnerImageForm::kraken_compressed;
    }

    try {
        std::vector<std::byte> inner;
        std::vector<std::byte> naps_layout;
        std::array<std::byte, image_digest_size> nested_image_digest{};
        std::uint64_t nested_image_size = 0;
        std::uint64_t nested_logical_size = 0;
        std::uint64_t nested_meta_base_blocks = 0;
        std::uint32_t nested_inner_content_inodes = 0;
        std::uint32_t nested_app_file_count = 0;
        std::uint32_t playgo_file_count = 0;
        std::vector<SiContentFile> si_content_files;
        std::optional<InnerPfsLayout> si_inner_layout;
        std::vector<std::byte> si_playgo_chunk;
        if (options.output_format == BuildOutputFormat::debug_image) {
            // Package images use SharpProspero's data-first inner layout. The
            // standalone builder remains available for the public inner-image
            // API and for metadata-only output.
            std::vector<InnerPfsFile> files;
            bool has_keystone = false;
            bool has_right_sprx = false;
            for (const auto& file : enumerate_source_files(options.source_folder)) {
                if (excluded_from_package_inner(file.relative_path)) {
                    continue;
                }
                if (file.relative_path == "sce_sys/keystone") {
                    has_keystone = true;
                }
                if (file.relative_path == "sce_sys/about/right.sprx") {
                    has_right_sprx = true;
                }
                files.push_back(InnerPfsFile{file.relative_path, read_file_bytes(file.full_path)});
            }
            if (!has_keystone) {
                files.push_back(InnerPfsFile{"sce_sys/keystone", create_keystone(options.passcode)});
            }
            if (!has_right_sprx) {
                auto right_sprx = load_optional_right_sprx();
                if (right_sprx.empty()) {
                    throw std::runtime_error(
                        "Missing SharpProspero debug right.sprx; reinstall the SDK or set "
                        "PROSPERO_PKG_RIGHT_SPRX to the reference resource.");
                }
                files.push_back(InnerPfsFile{"sce_sys/about/right.sprx", std::move(right_sprx)});
            }
            auto layout = build_inner_pfs_layout(std::move(files), 0, 0);
            si_content_files.reserve(layout.placements.size() + 1);
            for (std::size_t index = 0; index < layout.placements.size(); ++index) {
                si_content_files.push_back(SiContentFile{
                    layout.afid_paths.at(index), layout.placements[index].uncompressed_size});
            }
            inner = layout.image;
            naps_layout = build_naps_layout(layout);
            // FIH 0xA8/0xB0 describe the generated naps_pkg_layout.dat map,
            // while the outer PFS inode's SizeCompressed records the logical
            // size of the mounted inner image.
            nested_image_digest = sha3_256(naps_layout);
            nested_image_size = naps_layout.size();
            nested_logical_size = static_cast<std::uint64_t>(layout.logical_block_count) * pfs_block_size;
            nested_meta_base_blocks = layout.metadata_base_logical / pfs_block_size;
            nested_inner_content_inodes = static_cast<std::uint32_t>(layout.inode_count);
            nested_app_file_count = static_cast<std::uint32_t>(layout.app_file_count);
            // Sharp counts every non-directory node in the inner image,
            // including the three synthetic metadata files represented by
            // the package-level FICM descriptor.
            playgo_file_count = static_cast<std::uint32_t>(layout.placements.size() + 3u);
            si_inner_layout = layout;
            write_file_bytes(inner_tmp, inner);
        } else {
            (void)build_inner_image(InnerImageBuildOptions{
                options.source_folder,
                inner_tmp,
                options.content_id,
                options.passcode,
                form});
            inner = read_file_bytes(inner_tmp);
        }
        std::optional<OuterPfsPackageImage> outer;
        std::array<std::byte, 16> outer_seed{};
        if (options.output_format == BuildOutputFormat::debug_image) {
            outer_seed = deterministic_seed(options.content_id, options.passcode, std::span<const SourceFile>{});
            const auto naps_size = static_cast<std::uint64_t>(naps_layout.size());
            outer = build_outer_pfs_for_package(
                std::vector<OuterPfsFile>{
                    OuterPfsFile{"pfs_image.dat", inner, nested_logical_size, false},
                    OuterPfsFile{"naps_pkg_layout.dat", std::move(naps_layout), naps_size, true}},
                OuterPfsBuildParameters{0, 0, outer_seed},
                derive_ekpfs(options.content_id, options.passcode));
        }

        PkgWriterOptions writer;
        writer.content_id = options.content_id;
        writer.passcode = options.passcode;
        writer.flags = cnt_flags_ps5;
        writer.drm_type = 0;
        writer.content_type = content_type_for(options.mode);
        writer.content_flags = options.mode == BuildMode::additional_content_no_data ? 0u : 0x02020000u;
        // Keep the same body-order staging as SharpProspero: param.json,
        // imagedigs.dat, playgo-chunk.dat, media, then the remaining PlayGo
        // descriptors.  CNT metadata records are sorted by id later, but
        // data offsets intentionally follow this insertion order.
        writer.entries.push_back(PkgWriterEntry{
            static_cast<std::uint32_t>(EntryId::param_json),
            "param.json",
            param_json_bytes(options),
            0,
            0});
        if (outer) {
            writer.pfs_image_size = outer->ciphertext.size();
            writer.pfs_image_digest = outer->superblock_digest;
            writer.pfs_image_digests = outer->image_digests;
            writer.image_seed = outer_seed;
            const auto fih_header = build_fih_header(outer->ciphertext, outer->superblock_index,
                outer->superblock_digest, nested_image_digest, nested_image_size, nested_meta_base_blocks,
                nested_inner_content_inodes, nested_app_file_count, content_version_high(options.version));
            writer.pfs_signed_digest = compute_fixed_info_digest(fih_header);

            const auto rounded_inner = align_up(inner.size(), pfs_block_size);
            const auto combined_size = static_cast<std::uint64_t>(pfs_block_size) + outer->ciphertext.size();
            const auto mchunk0_size = rounded_inner > 0 && rounded_inner < combined_size
                ? rounded_inner : combined_size - pfs_block_size;
            const auto mchunk1_size = combined_size - mchunk0_size;
            writer.entries.push_back(PkgWriterEntry{
                0x040Au, "", {}, 0x08000000u, 0});
            writer.entries.push_back(PkgWriterEntry{
                static_cast<std::uint32_t>(EntryId::playgo_chunk_dat), "playgo-chunk.dat",
                build_playgo_chunk_dat(options.content_id, mchunk0_size, mchunk1_size), 0x08000000u, 0});
            si_playgo_chunk = build_playgo_chunk_dat(options.content_id, mchunk0_size, mchunk1_size);
        }
        for (auto& media : collect_media_entries(options.source_folder)) {
            const auto duplicate = std::any_of(writer.entries.begin(), writer.entries.end(), [&](const auto& entry) {
                return entry.id == media.id;
            });
            if (!duplicate) writer.entries.push_back(std::move(media));
        }
        if (outer) {
            writer.entries.push_back(PkgWriterEntry{
                0x2010u, "playgo-hash-table.dat", build_playgo_hash_table(playgo_file_count / 2u), 0x08000000u, 0});
            writer.entries.push_back(PkgWriterEntry{
                0x2011u, "playgo-ficm.dat", build_playgo_ficm(playgo_file_count), 0x08000000u, 0});
        }
        auto cnt = write_cnt(writer);
        if (options.output_format == BuildOutputFormat::debug_image) {
            // Finalized FIH images share the outer PFS at FIH+0x10000. SharpProspero
            // rewrites the embedded CNT field from its standalone body offset to that
            // FIH-relative location before appending the CNT metadata.
            write_be64(cnt, 0x410, PkgLayout::fih_header_region_size);
        }
        if (options.output_format == BuildOutputFormat::metadata_container) {
            write_file_bytes(output_path, cnt);
        } else if (options.output_format == BuildOutputFormat::debug_image) {
            const auto fih_header = build_fih_header(outer->ciphertext, outer->superblock_index,
                outer->superblock_digest, nested_image_digest, nested_image_size, nested_meta_base_blocks,
                nested_inner_content_inodes, nested_app_file_count, content_version_high(options.version));
            std::vector<std::byte> mount_image;
            const auto cnt_offset = PkgLayout::fih_header_region_size + align_up(outer->ciphertext.size(), pfs_block_size);
            mount_image.reserve(static_cast<std::size_t>(cnt_offset + cnt.size()));
            mount_image.insert(mount_image.end(), fih_header.begin(), fih_header.end());
            mount_image.insert(mount_image.end(), outer->ciphertext.begin(), outer->ciphertext.end());
            mount_image.resize(static_cast<std::size_t>(cnt_offset), std::byte{});
            mount_image.insert(mount_image.end(), cnt.begin(), cnt.end());
            std::vector<std::byte> si;
            if (si_inner_layout.has_value()) {
                si_content_files.push_back(SiContentFile{"*PFSmetadata", outer->ciphertext.size()});
                si = build_si_archive(SiBuildOptions{
                    options.content_id,
                    normalize_content_version(options.version),
                    options.title,
                    mount_image,
                    si_playgo_chunk,
                    &*si_inner_layout,
                    si_content_files,
                    static_cast<std::uint64_t>(align_up(inner.size(), pfs_block_size)),
                    static_cast<std::uint64_t>(outer->ciphertext.size()),
                    outer->superblock_index,
                    read_be64(cnt, 0x30)});
            }
            write_fih_package(output_path, outer->ciphertext, cnt, outer->superblock_index,
                outer->superblock_digest, nested_image_digest, nested_image_size, nested_meta_base_blocks,
                nested_inner_content_inodes, nested_app_file_count, content_version_high(options.version), si);
        } else {
            throw std::invalid_argument("Unknown package output format.");
        }
    } catch (...) {
        std::filesystem::remove(inner_tmp);
        throw;
    }

    std::filesystem::remove(inner_tmp);
    return output_path;
}

} // namespace prosperopkg
