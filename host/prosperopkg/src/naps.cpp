// PS5 NAPS package-layout descriptor.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/naps.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace prosperopkg {
namespace {

constexpr std::uint64_t ublock = 0x40000;
constexpr std::uint32_t mod_256k = 0x3FFFF;
constexpr std::uint32_t clen_even_cap = 131070;

struct Plan {
    bool start_run = false;
    bool terminator = false;
    std::uint64_t on_disk_offset = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t even_length = 0;
    std::uint64_t stream_length = 0;
    std::uint8_t even = 0;
    std::uint8_t odd = 1;
    std::uint8_t predictor = 0;
    std::uint8_t shuffle = 0;
};

struct Info {
    bool run_base = false;
    std::uint32_t offset_mod = 0;
    std::uint32_t uoffset = 0;
    std::uint32_t clen_minus_one = 0;
    std::uint8_t even = 0;
    std::uint8_t odd = 0;
    std::uint8_t predictor = 0;
    std::uint8_t shuffle = 0;
    std::uint32_t tweak = 0;
    std::uint8_t key = 0;
    std::uint32_t offset_256k = 0;
};

void put16(std::vector<std::byte>& out, std::size_t at, std::uint16_t value)
{
    out[at] = static_cast<std::byte>(value & 0xffu);
    out[at + 1] = static_cast<std::byte>((value >> 8u) & 0xffu);
}

void put32(std::vector<std::byte>& out, std::size_t at, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out[at + i] = static_cast<std::byte>((value >> (8u * i)) & 0xffu);
    }
}

void put64(std::vector<std::byte>& out, std::size_t at, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out[at + i] = static_cast<std::byte>((value >> (8u * i)) & 0xffu);
    }
}

std::array<std::byte, 9> encode_info(const Info& entry)
{
    std::uint64_t word = entry.offset_mod & mod_256k;
    std::uint8_t high = 0;
    if (!entry.run_base) {
        word |= (static_cast<std::uint64_t>(entry.uoffset & mod_256k) << 19u);
        word |= (static_cast<std::uint64_t>(entry.clen_minus_one & 0x1FFFFu) << 37u);
        word |= (static_cast<std::uint64_t>(entry.even & 1u) << 54u);
        word |= (static_cast<std::uint64_t>(entry.odd & 1u) << 55u);
        word |= (static_cast<std::uint64_t>(entry.predictor & 7u) << 56u);
        word |= (static_cast<std::uint64_t>(entry.shuffle & 0xFu) << 59u);
    } else {
        word |= 0x40000u;
        word |= (static_cast<std::uint64_t>(entry.tweak & 0xFFFFFFFu) << 19u);
        word |= (static_cast<std::uint64_t>(entry.key & 3u) << 47u);
        word |= (static_cast<std::uint64_t>(entry.offset_256k & 0x7FFFu) << 49u);
        high = static_cast<std::uint8_t>((entry.offset_256k >> 15u) & 0x1FFu);
    }
    std::array<std::byte, 9> encoded{};
    for (unsigned i = 0; i < 8; ++i) {
        encoded[i] = static_cast<std::byte>((word >> (8u * i)) & 0xffu);
    }
    encoded[8] = static_cast<std::byte>(high);
    return encoded;
}

void add_raw_file_plans(std::vector<Plan>& plans, const InnerPfsPlacement& file)
{
    if (!file.store_raw) {
        plans.push_back(Plan{
            true, false, file.on_disk_offset, file.logical_offset,
            file.on_disk_size, file.on_disk_size, 0, 1, 2, 0});
        return;
    }
    auto add = [&](std::uint64_t disk, std::uint64_t logical, std::uint64_t even, std::uint64_t stream) {
        plans.push_back(Plan{
            disk == file.on_disk_offset, false, disk, logical, even, stream,
            static_cast<std::uint8_t>(even == ublock ? 1 : 0), 1, 0, 0});
    };
    const auto full = file.uncompressed_size / ublock;
    const auto remainder = file.uncompressed_size % ublock;
    for (std::uint64_t i = 0; i < full; ++i) {
        const auto disk = file.on_disk_offset + i * ublock;
        plans.push_back(Plan{
            (i == 0 || (i % 11u) == 0), false, disk,
            file.logical_offset + i * ublock, 65536, 524288, 1, 1, 4, 0});
    }
    if (remainder != 0 || full == 0) {
        const auto disk = file.on_disk_offset + full * ublock;
        add(disk, file.logical_offset + full * ublock, remainder, remainder);
    }
}

std::vector<Info> walk(const std::vector<Plan>& plans, std::vector<std::pair<std::size_t, std::uint64_t>>& logicals)
{
    std::vector<Info> infos;
    infos.reserve(plans.size() * 2);
    std::uint64_t compressed_offset = 0;
    for (const auto& block : plans) {
        if (block.start_run) {
            const auto disk_block = block.on_disk_offset / ublock;
            const auto run_base = 2u * disk_block;
            compressed_offset = run_base * ublock + (block.on_disk_offset % ublock);
            infos.push_back(Info{
                true,
                static_cast<std::uint32_t>(compressed_offset & mod_256k),
                0, 0, 0, 0, 0, 0,
                block.terminator ? 0u : static_cast<std::uint32_t>(block.on_disk_offset >> 15u),
                0,
                static_cast<std::uint32_t>(2u * disk_block)});
        }
        const auto index = infos.size();
        const auto uoffset = block.terminator ? 1u : static_cast<std::uint32_t>((block.logical_offset & mod_256k) * 2u & mod_256k);
        const auto clen = block.terminator ? 1u : static_cast<std::uint32_t>(std::min<std::uint64_t>(
            block.even_length == 0 ? 0 : (block.even_length - 1u) * 2u, clen_even_cap));
        infos.push_back(Info{
            false,
            static_cast<std::uint32_t>(compressed_offset & mod_256k),
            uoffset,
            clen,
            block.even,
            block.odd,
            block.predictor,
            block.shuffle,
            0, 0, 0});
        logicals.emplace_back(index, block.logical_offset);
        compressed_offset += block.stream_length;
    }
    return infos;
}

std::uint8_t checked_delta(std::int64_t value)
{
    if (value < 0 || value > 255) {
        throw std::runtime_error("NAPS u2c delta exceeds its byte-sized field");
    }
    return static_cast<std::uint8_t>(value);
}

} // namespace

std::vector<std::byte> build_naps_layout(const InnerPfsLayout& image)
{
    if (image.image.empty() || image.afid_logical_offsets.empty()) {
        throw std::invalid_argument("NAPS requires a non-empty data-first inner image");
    }
    std::vector<Plan> plans;
    for (const auto& file : image.placements) {
        add_raw_file_plans(plans, file);
    }

    const auto gap = image.metadata_base_logical > image.data_end_logical
        ? image.metadata_base_logical - image.data_end_logical : 0;
    const auto gap_blocks = (gap + ublock - 1u) / ublock;
    for (std::uint64_t i = 0; i < gap_blocks; ++i) {
        plans.push_back(Plan{
            i + 1u < gap_blocks, false, image.block_info_on_disk_offset,
            image.data_end_logical + i * ublock, 8, 16, 0, 1, 4, 0});
    }
    const bool compressed_metadata = std::any_of(image.metadata_blocks.begin(), image.metadata_blocks.end(),
        [](const auto& block) { return block.compressed; });
    for (std::size_t i = 0; i < image.metadata_blocks.size(); ++i) {
        const auto& block = image.metadata_blocks[i];
        const auto even_length = compressed_metadata
            ? (block.multi_chunk ? block.first_chunk_compressed_size : block.on_disk_size)
            : block.uncompressed_size;
        plans.push_back(Plan{
            i == 0, false, block.on_disk_offset,
            image.metadata_base_logical + static_cast<std::uint64_t>(i) * ublock,
            even_length, block.on_disk_size, 0, 1,
            static_cast<std::uint8_t>(compressed_metadata ? 2 : 4),
            static_cast<std::uint8_t>(compressed_metadata && i + 1 < image.metadata_blocks.size() ? 2 : 0)});
    }
    const auto metadata_size = image.image.size() - image.metadata_on_disk_offset;
    plans.push_back(Plan{true, true, image.metadata_on_disk_offset + metadata_size,
        static_cast<std::uint64_t>(image.logical_block_count * 0x10000ll), 0, 0, 0, 0, 0, 0});

    std::vector<std::pair<std::size_t, std::uint64_t>> logicals;
    const auto infos = walk(plans, logicals);
    const auto outer_blocks = (image.image.size() + 0xFFFFu) / 0x10000u;
    const auto num_u_blocks = (image.logical_block_count * 0x10000ll + ublock - 1u) / ublock;
    const auto num_groups = (num_u_blocks + 7u) / 8u;
    const auto file_count = image.afid_logical_offsets.size() + 3u;
    const auto cblock_count = infos.size();
    const std::uint64_t header0 = ((file_count - 1u) & 0xFFFFFFu) |
        (static_cast<std::uint64_t>(2u) << 24u) |
        (static_cast<std::uint64_t>(0u) << 26u) |
        (static_cast<std::uint64_t>(num_u_blocks & 0xFFFFFFu) << 32u);
    const std::uint64_t header1 = (outer_blocks & 0xFFFFFFu) |
        (static_cast<std::uint64_t>((cblock_count - 2u) & 0xFFFFFFu) << 24u);
    const auto fidx_count = file_count + 1u;
    const auto total = 16u + outer_blocks * 8u + fidx_count * 6u + num_groups * 10u + cblock_count * 9u;
    std::vector<std::byte> out((total + 15u) & ~std::size_t{15u});
    put64(out, 0, header0);
    put64(out, 8, header1);
    std::size_t cursor = 16;
    cursor += outer_blocks * 8u; // no outer digest table is supplied by nwonly
    for (std::size_t i = 0; i < image.afid_logical_offsets.size(); ++i) {
        for (unsigned j = 0; j < 5; ++j) {
            out[cursor + j] = static_cast<std::byte>((image.afid_logical_offsets[i] >> (8u * j)) & 0xffu);
        }
        out[cursor + 5] = std::byte{0};
        cursor += 6;
    }
    const auto end_logical = image.data_end_logical;
    for (unsigned j = 0; j < 5; ++j) {
        out[cursor + j] = static_cast<std::byte>((end_logical >> (8u * j)) & 0xffu);
    }
    out[cursor + 5] = std::byte{0};
    cursor += 6;
    const auto meta_logical = image.metadata_base_logical;
    for (unsigned j = 0; j < 5; ++j) {
        out[cursor + j] = static_cast<std::byte>((meta_logical >> (8u * j)) & 0xffu);
    }
    out[cursor + 5] = std::byte{0};
    cursor += 6;
    const auto image_logical = static_cast<std::uint64_t>(image.logical_block_count * 0x10000ll);
    for (unsigned j = 0; j < 5; ++j) {
        out[cursor + j] = static_cast<std::byte>((image_logical >> (8u * j)) & 0xffu);
    }
    out[cursor + 5] = std::byte{64};
    cursor += 6;
    // The required trailer is a synthetic fidx entry, matching SharpProspero.
    out[cursor + 0] = std::byte{1}; out[cursor + 1] = std::byte{0}; out[cursor + 2] = std::byte{0};
    out[cursor + 3] = std::byte{5}; out[cursor + 4] = std::byte{6}; out[cursor + 5] = std::byte{7};
    cursor += 6;
    std::vector<std::pair<std::size_t, std::uint64_t>> sorted = logicals;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
    std::vector<std::size_t> first(static_cast<std::size_t>(num_u_blocks));
    std::size_t pos = 0;
    for (std::size_t group = 0; group < first.size(); ++group) {
        const auto logical = static_cast<std::uint64_t>(group) * ublock;
        while (pos < sorted.size() && sorted[pos].second < logical) ++pos;
        first[group] = pos < sorted.size() ? sorted[pos].first : infos.size() - 1u;
    }
    for (std::size_t group = 0; group < num_groups; ++group) {
        const auto base_index = group * 8u;
        const auto base = first[base_index];
        std::array<std::byte, 10> u2c{};

        const auto index_for = [&](std::size_t index) {
            return index < first.size() ? first[index] : infos.size() - 1u;
        };
        for (unsigned delta = 0; delta < 4; ++delta) {
            const auto target = index_for(base_index + 4u + delta);
            u2c[delta] = static_cast<std::byte>(checked_delta(
                static_cast<std::int64_t>(target) - static_cast<std::int64_t>(base)));
        }

        const bool has_next_group = base_index + 8u < first.size();
        if (has_next_group) {
            const auto next_base = first[base_index + 8u];
            u2c[4] = static_cast<std::byte>(checked_delta(next_base));
            for (unsigned delta = 0; delta < 3; ++delta) {
                const auto target = index_for(base_index + 9u + delta);
                u2c[7u + delta] = static_cast<std::byte>(checked_delta(
                    static_cast<std::int64_t>(target) - static_cast<std::int64_t>(next_base)));
            }
        }
        std::copy(u2c.begin(), u2c.end(), out.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += 10;
    }
    for (const auto& info : infos) {
        const auto encoded = encode_info(info);
        std::copy(encoded.begin(), encoded.end(), out.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += encoded.size();
    }
    return out;
}

} // namespace prosperopkg
