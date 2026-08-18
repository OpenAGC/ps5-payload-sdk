// LibProsperoPkg PS5 inner PFS layout port.
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace prosperopkg {

struct InnerPfsFile {
    std::string path;
    std::vector<std::byte> data;
};

struct InnerPfsBlockPlacement {
    std::uint64_t on_disk_offset = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t on_disk_size = 0;
    std::uint64_t uncompressed_size = 0;
    bool compressed = false;
    bool multi_chunk = false;
    std::uint64_t first_chunk_compressed_size = 0;
};

// Data-first PS5 images need the placement table when generating the
// accompanying naps_pkg_layout.dat descriptor.  Offsets are image-relative.
struct InnerPfsPlacement {
    std::uint64_t on_disk_offset = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t on_disk_size = 0;
    std::uint64_t uncompressed_size = 0;
    bool store_raw = true;
    std::vector<InnerPfsBlockPlacement> blocks;
};

struct InnerPfsLayout {
    std::vector<std::byte> image;
    std::int64_t logical_block_count = 0;
    std::int64_t metadata_logical_offset = 0;
    std::size_t inode_count = 0;
    std::size_t app_file_count = 0;
    std::vector<InnerPfsPlacement> placements;
    std::vector<std::uint64_t> afid_logical_offsets;
    // Content paths in the same AFID order as placements. This is required
    // by the NAPS SI file table and avoids reconstructing tree traversal.
    std::vector<std::string> afid_paths;
    std::uint64_t block_info_on_disk_offset = 0;
    std::uint64_t metadata_on_disk_offset = 0;
    std::uint64_t data_end_logical = 0;
    std::uint64_t metadata_base_logical = 0;
    std::vector<InnerPfsBlockPlacement> metadata_blocks;
    // Retained for validation and tooling parity with SharpProspero's
    // ProsperoPs5InnerImageResult.MetadataPlaintext.
    std::vector<std::byte> metadata_plaintext;
};

[[nodiscard]] InnerPfsLayout build_inner_pfs_layout(
    std::vector<InnerPfsFile> files,
    std::int64_t timestamp_seconds,
    std::uint32_t timestamp_nanoseconds = 0);

// Builds the standalone PS5 v2 PFS image used by BuildInnerPfsLayout.
// Unlike the package nested image, this result starts with a 64 KiB PFS
// superblock and can be encrypted or wrapped in PFSC directly.
[[nodiscard]] InnerPfsLayout build_standalone_pfs_layout(
    std::vector<InnerPfsFile> files,
    std::int64_t timestamp_seconds,
    std::uint32_t timestamp_nanoseconds = 0);

} // namespace prosperopkg
