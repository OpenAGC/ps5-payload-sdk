#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace prosperopkg {

constexpr std::size_t image_digest_block_size = 0x10000;
constexpr std::size_t image_digest_size = 32;
constexpr std::size_t package_digest_region_size = 0xFE0;

struct CntDigestPayload { std::uint32_t id = 0; std::span<const std::byte> payload{}; };
struct SblockDigestResult { std::size_t offset = 0; std::array<std::byte, 32> digest{}; };

[[nodiscard]] std::array<std::byte, 32> compute_sblock_digest(std::span<const std::byte> block);
[[nodiscard]] std::array<std::byte, 32> compute_game_digest(std::span<const std::byte> block);
[[nodiscard]] std::array<std::byte, 32> compute_fixed_info_digest(std::span<const std::byte> block);
[[nodiscard]] std::array<std::byte, 32> compute_body_digest(std::span<const std::byte> body);
[[nodiscard]] std::array<std::byte, 32> compute_entry_digest(std::span<const std::byte> payload);
[[nodiscard]] std::array<std::byte, 32> compute_content_digest(std::span<const std::byte> descriptor,
    std::span<const std::byte> game, std::span<const std::byte> major_param, bool include_game);
[[nodiscard]] std::array<std::byte, 32> compute_header_digest(std::span<const std::byte> prefix,
    std::span<const std::byte> mount_descriptor);
[[nodiscard]] std::array<std::byte, 128> force_fih_relative_image_offset(std::span<const std::byte> descriptor);
[[nodiscard]] std::array<std::byte, 32> compute_package_digest(std::span<const std::byte> cnt);
[[nodiscard]] std::optional<SblockDigestResult> compute_sblock_digest_from_image(
    std::span<const std::byte> image, std::size_t block_size = image_digest_block_size);

} // namespace prosperopkg
