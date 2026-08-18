// SharpProspero-compatible outer PS5 PFS layout.
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prosperopkg {

struct OuterPfsFile {
    std::string name;
    std::vector<std::byte> data;
    std::uint64_t size_compressed = 0;
    bool signed_data = false;
};

struct OuterPfsBuildParameters {
    std::int64_t timestamp_seconds = 0;
    std::uint32_t timestamp_nanoseconds = 0;
    std::array<std::byte, 16> seed{};
};

struct OuterPfsPackageImage {
    std::vector<std::byte> ciphertext;
    std::vector<std::byte> image_digests;
    std::array<std::byte, 32> superblock_icv{};
    std::array<std::byte, 32> superblock_digest{};
    std::size_t superblock_index = 0;
};

[[nodiscard]] OuterPfsPackageImage build_outer_pfs_for_package(
    std::vector<OuterPfsFile> files,
    const OuterPfsBuildParameters& parameters,
    std::span<const std::byte> ekpfs);

} // namespace prosperopkg
