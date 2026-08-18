// PS5 NAPS package-layout descriptor.
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <prosperopkg/pfs_layout.hpp>

namespace prosperopkg {

// Generate the nwonly naps_pkg_layout.dat descriptor for a data-first inner
// image, including raw and Kraken-compressed data/metadata placements.
[[nodiscard]] std::vector<std::byte> build_naps_layout(const InnerPfsLayout& image);

} // namespace prosperopkg
