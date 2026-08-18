// SharpProspero parity regressions for the native package builder.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/build.hpp>
#include <prosperopkg/hash.hpp>
#include <prosperopkg/naps.hpp>
#include <prosperopkg/outer_pfs.hpp>
#include <prosperopkg/pfs_image.hpp>
#include <prosperopkg/pfs_layout.hpp>
#include <prosperopkg/pfs_keys.hpp>
#include <prosperopkg/pkg.hpp>
#include <prosperopkg/self.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t block_size = 0x10000;

void expect(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::uint16_t read_le16(std::span<const std::byte> data, std::size_t offset)
{
    return static_cast<std::uint16_t>(data[offset]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[offset + 1]) << 8u);
}

std::uint32_t read_le32(std::span<const std::byte> data, std::size_t offset)
{
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(data[offset + index]) << (index * 8u);
    }
    return value;
}

std::uint64_t read_le64(std::span<const std::byte> data, std::size_t offset)
{
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(data[offset + index]) << (index * 8u);
    }
    return value;
}

std::uint64_t read_be64(std::span<const std::byte> data, std::size_t offset)
{
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value = (value << 8u) | static_cast<std::uint8_t>(data[offset + index]);
    }
    return value;
}

std::size_t find_ascii(std::span<const std::byte> data, std::string_view value)
{
    const auto begin = reinterpret_cast<const std::byte*>(value.data());
    const auto it = std::search(data.begin(), data.end(), begin, begin + value.size());
    return it == data.end() ? data.size() : static_cast<std::size_t>(it - data.begin());
}

void write_le16(std::span<std::byte> data, std::size_t offset, std::uint16_t value)
{
    data[offset] = static_cast<std::byte>(value & 0xffu);
    data[offset + 1] = static_cast<std::byte>(value >> 8u);
}

void write_le32(std::span<std::byte> data, std::size_t offset, std::uint32_t value)
{
    for (unsigned index = 0; index < 4; ++index) {
        data[offset + index] = static_cast<std::byte>(value >> (index * 8u));
    }
}

void write_le64(std::span<std::byte> data, std::size_t offset, std::uint64_t value)
{
    for (unsigned index = 0; index < 8; ++index) {
        data[offset + index] = static_cast<std::byte>(value >> (index * 8u));
    }
}

std::vector<std::byte> make_minimal_elf()
{
    std::vector<std::byte> elf(0x1010);
    elf[0] = std::byte{0x7f};
    elf[1] = std::byte{'E'};
    elf[2] = std::byte{'L'};
    elf[3] = std::byte{'F'};
    elf[4] = std::byte{2};
    elf[5] = std::byte{1};
    elf[6] = std::byte{1};
    write_le32(elf, 0x14, 1);
    write_le64(elf, 0x20, 0x40);
    write_le16(elf, 0x34, 0x40);
    write_le16(elf, 0x36, 0x38);
    write_le16(elf, 0x38, 1);

    write_le32(elf, 0x40, 1);
    write_le32(elf, 0x44, 5);
    write_le64(elf, 0x48, 0x1000);
    write_le64(elf, 0x50, 0x400000);
    write_le64(elf, 0x58, 0x400000);
    write_le64(elf, 0x60, 0x10);
    write_le64(elf, 0x68, 0x10);
    write_le64(elf, 0x70, 0x1000);
    for (std::size_t index = 0; index < 0x10; ++index) {
        elf[0x1000 + index] = static_cast<std::byte>(0x90u + index);
    }
    return elf;
}

std::vector<std::byte> read_file(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    expect(static_cast<bool>(input), "could not open " + path.string());
    input.seekg(0, std::ios::end);
    const auto length = input.tellg();
    expect(length >= 0, "could not size " + path.string());
    input.seekg(0, std::ios::beg);
    std::vector<std::byte> data(static_cast<std::size_t>(length));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        expect(static_cast<bool>(input), "could not read " + path.string());
    }
    return data;
}

void write_file(const fs::path& path, std::span<const std::byte> data)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    expect(static_cast<bool>(output), "could not create " + path.string());
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    expect(static_cast<bool>(output), "could not write " + path.string());
}

struct TempDirectory {
    fs::path path;

    TempDirectory()
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path = fs::temp_directory_path() / ("prospero-pkg-regression-" + std::to_string(nonce));
        fs::create_directories(path);
    }

    ~TempDirectory()
    {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

void test_fself_layout()
{
    const auto elf = make_minimal_elf();
    const auto self = prosperopkg::make_fself(elf);
    expect(prosperopkg::is_self(self), "fake SELF magic differs from SharpProspero");
    expect(prosperopkg::validate_self(self), "generated fake SELF failed validation");
    expect(read_le32(self, 0) == 0xEEF51454u, "fake SELF magic field is wrong");
    expect(read_le16(self, 0x0c) == 0x150u, "fake SELF header size is wrong");
    expect(read_le16(self, 0x0e) == 0x390u, "fake SELF metadata footer size is wrong");
    expect(read_le16(self, 0x18) == 2u, "fake SELF segment count is wrong");
    expect(self.size() == 0x510u, "fake SELF output length is wrong");
    const auto parsed = prosperopkg::parse_self(self);
    expect(parsed.program_type == 0x101u, "fake SELF program type differs from SharpProspero");
    expect(parsed.segments.size() == 2u, "fake SELF segment table did not round-trip");
    expect(parsed.ext_info.has_value(), "fake SELF extended info is missing");
    expect(parsed.ext_info->authority_id == 0x3100000000000002ull,
        "fake SELF authority id differs from SharpProspero");
    for (const auto& segment : parsed.segments) {
        expect(!segment.encrypted(), "debug fake SELF segment is unexpectedly encrypted");
    }
    expect(parsed.elf.size() == 0x78u, "embedded ELF header length is wrong");
    expect(read_le16(parsed.elf, 0x10) == 2u, "embedded ELF type was not normalized");
    expect(read_le16(parsed.elf, 0x12) == 62u, "embedded ELF machine was not normalized");
    expect(parsed.elf[7] == std::byte{9}, "embedded ELF OS ABI was not normalized");

    auto alternate = self;
    write_le32(alternate, 0, prosperopkg::SelfLayout::alternate_magic);
    expect(prosperopkg::is_self(alternate), "alternate SharpProspero SELF magic was rejected");
    expect(prosperopkg::validate_self(alternate), "alternate SharpProspero SELF failed validation");
}

void test_fself_rejects_invalid_selected_segment()
{
    auto elf = make_minimal_elf();
    write_le64(elf, 0x60, 0x10000);
    bool rejected = false;
    try {
        (void)prosperopkg::make_fself(elf);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    expect(rejected, "out-of-range selected ELF segment was accepted");
}

void test_fself_preserves_version_records()
{
    auto elf = make_minimal_elf();
    elf.resize(0x1018);
    write_le16(elf, 0x38, 2);
    write_le32(elf, 0x78, 0x6FFFFF01u);
    write_le64(elf, 0x80, 0x1008);
    write_le64(elf, 0x98, 8);
    for (std::size_t index = 0; index < 8; ++index) {
        elf[0x1008 + index] = static_cast<std::byte>(0xD0u + index);
    }

    const auto self = prosperopkg::make_fself(elf);
    const auto header_file_size = read_le64(self, 0x10);
    expect(self.size() == header_file_size + 8u,
        "SELF version records were not appended after the stored segments");
    for (std::size_t index = 0; index < 8; ++index) {
        expect(self[static_cast<std::size_t>(header_file_size) + index] ==
                static_cast<std::byte>(0xD0u + index),
            "SELF version-record bytes differ from the ELF tail");
    }
}

void test_cnt_pfs_flags()
{
    prosperopkg::PkgWriterOptions options;
    options.content_id = "UP0000-FAKE02932_00-0000000000000000";
    options.passcode = "00000000000000000000000000000000";
    const auto cnt = prosperopkg::write_cnt(options);
    expect(cnt.size() >= 0x410u, "CNT image is too small");
    expect(read_be64(cnt, 0x408) == 0xA00000000000030Cull,
        "CNT PFS flags differ from SharpProspero");
}

std::vector<prosperopkg::InnerPfsFile> fixture_files(const std::vector<std::byte>& self)
{
    std::vector<std::byte> keystone(96);
    for (std::size_t index = 0; index < keystone.size(); ++index) {
        keystone[index] = static_cast<std::byte>((index * 37u + 11u) & 0xffu);
    }
    std::vector<std::byte> param(1024, std::byte{'P'});
    std::vector<std::byte> readme(8192);
    for (std::size_t index = 0; index < readme.size(); ++index) {
        readme[index] = static_cast<std::byte>("SharpProspero"[index % 13u]);
    }
    return {
        {"readme.txt", std::move(readme)},
        {"sce_sys/param.json", std::move(param)},
        {"eboot.bin", self},
        {"sce_sys/keystone", std::move(keystone)},
    };
}

void test_inner_layout_and_naps()
{
    const auto self = prosperopkg::make_fself(make_minimal_elf());
    const auto layout = prosperopkg::build_inner_pfs_layout(fixture_files(self), 0, 0);
    expect(!layout.image.empty(), "inner data-first image is empty");
    expect(!layout.metadata_plaintext.empty(), "inner metadata plaintext was not retained");
    expect(layout.metadata_base_logical ==
            static_cast<std::uint64_t>(layout.logical_block_count) * block_size -
                layout.metadata_plaintext.size(),
        "inner metadata logical base differs from SharpProspero");

    const auto inode_flt = 3u * block_size;
    expect(layout.metadata_plaintext.size() >= inode_flt + 0x40u,
        "inner inode FLT is outside metadata plaintext");
    const auto flt_count = read_le32(layout.metadata_plaintext, inode_flt + 0x2c);
    expect(flt_count == 5u, "inner inode FLT entry count is wrong");
    std::array<bool, 10> found{};
    std::array<bool, 10> subtree{};
    for (std::uint32_t index = 0; index < flt_count; ++index) {
        const auto packed = read_le64(layout.metadata_plaintext, inode_flt + 0x40u + index * 16u + 8u);
        const auto inode = static_cast<std::size_t>(packed & 0xffffffu);
        if (inode < found.size()) {
            found[inode] = true;
            subtree[inode] = (packed & 0x80000000ull) != 0;
        }
    }
    expect(found[5] && !subtree[5], "sce_sys directory FLT flags are wrong");
    expect(found[6] && subtree[6], "sce_sys/keystone FLT subtree bit is wrong");
    expect(found[7] && subtree[7], "sce_sys/param.json FLT subtree bit is wrong");
    expect(found[8] && !subtree[8], "eboot.bin FLT subtree bit is wrong");
    expect(found[9] && !subtree[9], "readme.txt FLT subtree bit is wrong");

    const auto apr_flt = 4u * block_size;
    expect(read_le32(layout.metadata_plaintext, apr_flt + 0x2c) == 2u,
        "APR FLT must contain only non-sce_sys files");

    const auto naps = prosperopkg::build_naps_layout(layout);
    const auto header0 = read_le64(naps, 0);
    const auto header1 = read_le64(naps, 8);
    const auto num_files = static_cast<std::size_t>((header0 & 0xffffffu) + 1u);
    const auto num_u_blocks = static_cast<std::size_t>((header0 >> 32u) & 0xffffffu);
    const auto outer_blocks = static_cast<std::size_t>(header1 & 0xffffffu);
    const auto cblock_count = static_cast<std::size_t>(((header1 >> 24u) & 0xffffffu) + 2u);
    expect(((header0 >> 24u) & 3u) == 2u, "NAPS compression type is not Kraken");
    expect(((header0 >> 26u) & 3u) == 0u, "NAPS key count is not one");
    expect(((header0 >> 28u) & 0xfu) == 0u, "NAPS shuffle-pattern count is wrong");
    expect(num_files == layout.afid_logical_offsets.size() + 3u, "NAPS file count is wrong");
    expect(cblock_count >= 2u, "NAPS CblockInfo count is invalid");

    const auto fidx_offset = 16u + outer_blocks * 8u;
    for (std::size_t index = 0; index + 1u < num_files; ++index) {
        expect(naps[fidx_offset + index * 6u + 5u] == std::byte{0},
            "NAPS non-final FIDX entry has a nonzero type");
    }
    expect(naps[fidx_offset + (num_files - 1u) * 6u + 5u] == std::byte{0x40},
        "NAPS mount-size FIDX entry is not type 0x40");
    constexpr std::array<std::byte, 6> trailer{
        std::byte{1}, std::byte{0}, std::byte{0}, std::byte{5}, std::byte{6}, std::byte{7}};
    expect(std::equal(trailer.begin(), trailer.end(), naps.begin() +
            static_cast<std::ptrdiff_t>(fidx_offset + num_files * 6u)),
        "NAPS FIDX trailer differs from SharpProspero");

    const auto group_count = (num_u_blocks + 7u) / 8u;
    const auto u2c_offset = fidx_offset + (num_files + 1u) * 6u;
    expect(group_count > 0u, "NAPS U2C table is empty");
    const auto final_group = u2c_offset + (group_count - 1u) * 10u;
    expect(naps[final_group + 4u] == std::byte{0},
        "NAPS final partial U2C group has a next-base index");
    expect(naps[final_group + 7u] == std::byte{0} &&
            naps[final_group + 8u] == std::byte{0} &&
            naps[final_group + 9u] == std::byte{0},
        "NAPS final partial U2C group has next-group deltas");
}

void test_package_fih_uses_naps_size()
{
    TempDirectory temp;
    const auto self = prosperopkg::make_fself(make_minimal_elf());
    auto files = fixture_files(self);
    files.push_back({"sce_sys/about/right.sprx", read_file(fs::path("prosperopkg/data/right.sprx"))});
    for (const auto& file : files) {
        write_file(temp.path / "app" / file.path, file.data);
    }

    auto package_inner_files = files;
    package_inner_files.erase(
        std::remove_if(package_inner_files.begin(), package_inner_files.end(), [](const auto& file) {
            return file.path == "sce_sys/param.json";
        }),
        package_inner_files.end());
    const auto inner = prosperopkg::build_inner_pfs_layout(std::move(package_inner_files), 0, 0);
    const auto naps = prosperopkg::build_naps_layout(inner);

    prosperopkg::PackageBuildOptions options;
    options.source_folder = temp.path / "app";
    options.output_folder = temp.path / "out";
    options.content_id = "UP0000-FAKE02932_00-0000000000000000";
    options.passcode = "00000000000000000000000000000000";
    options.title = "Native & regression <test>";
    options.title_id = "FAKE02932";
    options.version = "02.003.004";
    options.mode = prosperopkg::BuildMode::homebrew;
    options.output_format = prosperopkg::BuildOutputFormat::debug_image;

    const auto package_path = prosperopkg::build_package(options);
    const auto package = read_file(package_path);
    expect(package.size() >= block_size, "generated package is smaller than its FIH region");
    expect(read_le32(package, 0) == 0x4849467fu, "generated package is missing FIH magic");
    expect(read_le64(package, 0xa8) == naps.size(),
        "FIH 0xA8 must contain naps_pkg_layout.dat length");
    expect(read_le64(package, 0x50) == inner.metadata_base_logical / block_size,
        "FIH 0x50 must contain the nested metadata-base block index");
    const auto naps_digest = prosperopkg::sha3_256(naps);
    expect(std::equal(naps_digest.begin(), naps_digest.end(), package.begin() + 0xb0),
        "FIH 0xB0 must contain SHA3-256(naps_pkg_layout.dat)");

    const auto cnt_offset = static_cast<std::size_t>(read_le64(package, 0x58));
    expect(cnt_offset + 0x418 <= package.size(), "generated package has no embedded CNT header");
    expect(read_be64(package, cnt_offset + 0x410) == block_size,
        "embedded CNT PFS offset is not FIH-relative");
    const auto si_offset = cnt_offset + static_cast<std::size_t>(read_be64(package, cnt_offset + 0x4b8));
    expect(si_offset + 4 <= package.size() &&
            package[si_offset] == std::byte{'P'} && package[si_offset + 1] == std::byte{'K'} &&
            package[si_offset + 2] == std::byte{3} && package[si_offset + 3] == std::byte{4},
        "generated package is missing the trailing SI ZIP");
    constexpr std::array<std::string_view, 8> si_members{
        "common/etc/naps_meta_18.dat", "common/etc/naps_meta_300.dat",
        "common/etc/naps_meta_301.dat", "common/etc/naps_meta_302.dat",
        "common/etc/naps_meta_308.dat", "common/etc/pfsimage.xml",
        "common/etc/playgo-chunk.dat",
        "config/UP0000-FAKE02932_00-0000000000000000/playgo-chunk.crc"};
    std::size_t previous = si_offset;
    for (const auto member : si_members) {
        const auto location = find_ascii(std::span<const std::byte>(package).subspan(si_offset), member);
        expect(location != package.size() - si_offset, "SI ZIP is missing a required member");
        expect(si_offset + location >= previous, "SI ZIP member order is not canonical");
        previous = si_offset + location;
    }
    const auto meta_name = find_ascii(std::span<const std::byte>(package).subspan(si_offset),
        "common/etc/naps_meta_300.dat");
    expect(meta_name != package.size() - si_offset, "SI ZIP has no naps_meta_300 record");
    const auto meta_data = si_offset + meta_name + std::string_view("common/etc/naps_meta_300.dat").size();
    expect(meta_data + 48 <= package.size(), "naps_meta_300 record is truncated");
    const auto inner_size = read_le64(package, 0xa0);
    expect(read_le64(package, meta_data + 0x10) == inner_size - block_size &&
            read_le64(package, meta_data + 0x18) == 0x3e9 &&
            read_le64(package, meta_data + 0x20) == inner_size - block_size &&
            read_le64(package, meta_data + 0x28) == block_size,
        "naps_meta_300 geometry does not match the FIH inner image");
    const auto crc_name = find_ascii(std::span<const std::byte>(package).subspan(si_offset), si_members.back());
    const auto crc_data = si_offset + crc_name + si_members.back().size();
    expect(crc_data + ((si_offset / block_size) * 4) <= package.size(),
        "playgo-chunk.crc does not cover every pre-SI mount block");
    const auto xml_offset = find_ascii(std::span<const std::byte>(package).subspan(si_offset),
        "common/etc/pfsimage.xml");
    expect(xml_offset != package.size() - si_offset, "SI ZIP has no pfsimage.xml");
    const auto xml_begin = si_offset + xml_offset + std::string_view("common/etc/pfsimage.xml").size();
    const auto xml_end = find_ascii(std::span<const std::byte>(package).subspan(xml_begin), "</package-configuration>");
    expect(xml_end != package.size() - xml_begin, "pfsimage.xml is truncated");
    const auto xml = std::span<const std::byte>(package).subspan(xml_begin, xml_end + std::string_view("</package-configuration>").size());
    expect(find_ascii(xml, "Native &amp; regression &lt;test&gt;") != xml.size(),
        "pfsimage.xml did not escape XML text");
    expect(find_ascii(xml, "<masterVersion>02.00</masterVersion>") != xml.size(),
        "pfsimage.xml master version is not derived from the content version");
    expect(find_ascii(xml, "-C02003004-M0000000000000000-GD") != xml.size(),
        "pfsimage.xml longname is not derived from the content version");
    expect(find_ascii(xml, "<container-offset>0x") != xml.size(),
        "pfsimage.xml is missing the canonical container offset");
}

void test_outer_pfs_dirent_types()
{
    std::array<std::byte, 16> seed{};
    const auto ekpfs = prosperopkg::derive_ekpfs(
        "UP0000-FAKE02932_00-0000000000000000",
        "00000000000000000000000000000000");
    const auto outer = prosperopkg::build_outer_pfs_for_package(
        std::vector<prosperopkg::OuterPfsFile>{
            {"pfs_image.dat", std::vector<std::byte>(16), 16, false},
            {"naps_pkg_layout.dat", std::vector<std::byte>(16), 16, true}},
        prosperopkg::OuterPfsBuildParameters{0, 0, seed},
        ekpfs);

    auto plain = outer.ciphertext;
    const auto keys = prosperopkg::derive_image_encryption_keys(ekpfs, seed);
    std::vector<prosperopkg::OuterPfsBlockKind> kinds(
        plain.size() / block_size, prosperopkg::OuterPfsBlockKind::signed_block);
    kinds[0] = prosperopkg::OuterPfsBlockKind::data;
    kinds[outer.superblock_index] = prosperopkg::OuterPfsBlockKind::plaintext;
    expect(prosperopkg::transform_outer_pfs_image(plain, keys, block_size, kinds, false) == kinds.size() - 1u,
        "outer PFS decrypt did not transform every encrypted block");

    const auto root = (outer.superblock_index + 2u) * block_size;
    const auto uroot = (outer.superblock_index + 4u) * block_size;
    expect(read_le32(plain, root + 4u) == 2u, "outer FLT dirent is not a file");
    expect(read_le32(plain, root + 44u) == 3u, "outer uroot dirent is not a directory");
    expect(read_le32(plain, uroot + 4u) == 4u, "outer dot dirent type is wrong");
    expect(read_le32(plain, uroot + 28u) == 5u, "outer dot-dot dirent type is wrong");
    expect(read_le32(plain, uroot + 52u) == 2u, "outer content dirent is not a file");
}

} // namespace

int main()
{
    try {
        test_fself_layout();
        test_fself_rejects_invalid_selected_segment();
        test_fself_preserves_version_records();
        test_cnt_pfs_flags();
        test_inner_layout_and_naps();
        test_package_fih_uses_naps_size();
        test_outer_pfs_dirent_types();
        std::cout << "prospero-pkg regression tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "prospero-pkg regression failure: " << error.what() << '\n';
        return 1;
    }
}
