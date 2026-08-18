// Native builder for the debug finalized-image SI (install metadata) archive.
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <prosperopkg/pfs_layout.hpp>

namespace prosperopkg {

struct SiContentFile {
    std::string path;
    std::uint64_t size = 0;
};

struct SiBuildOptions {
    std::string content_id;
    std::string version = "01.000.000";
    std::string title;
    std::span<const std::byte> mount_image{};
    std::span<const std::byte> playgo_chunk_dat{};
    const InnerPfsLayout* inner = nullptr;
    std::span<const SiContentFile> content_files{};
    std::uint64_t inner_image_size = 0;
    std::uint64_t pfs_image_size = 0;
    std::size_t outer_superblock_index = 0;
    std::uint64_t mandatory_size = 0;
};

// Build the trailing debug SI ZIP. All entries are STORED and deterministic.
[[nodiscard]] std::vector<std::byte> build_si_archive(const SiBuildOptions& options);

} // namespace prosperopkg
