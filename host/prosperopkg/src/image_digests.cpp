#include <prosperopkg/image_digests.hpp>
#include <prosperopkg/hash.hpp>
#include <algorithm>
#include <stdexcept>

namespace prosperopkg {
namespace {
constexpr std::array<std::byte, 4> sb_magic{std::byte{0x0B}, std::byte{0x2A}, std::byte{0x33}, std::byte{0x01}};
void exact(std::span<const std::byte> s, std::size_t n, const char* what) {
    if (s.size() != n) throw std::invalid_argument(std::string(what) + " has an invalid size");
}
std::uint64_t le64(std::span<const std::byte> s) {
    std::uint64_t v = 0; for (unsigned i = 0; i != 8; ++i) v |= static_cast<std::uint64_t>(s[i]) << (i * 8); return v;
}
void be64(std::span<std::byte> s, std::uint64_t v) {
    for (unsigned i = 0; i != 8; ++i) s[i] = static_cast<std::byte>(v >> ((7 - i) * 8));
}
}
std::array<std::byte, 32> compute_sblock_digest(std::span<const std::byte> b) { exact(b, 0x10000, "superblock"); return sha3_256(b); }
std::array<std::byte, 32> compute_game_digest(std::span<const std::byte> b) { return compute_sblock_digest(b); }
std::array<std::byte, 32> compute_fixed_info_digest(std::span<const std::byte> b) { exact(b, 0x10000, "FIH"); return sha3_256(b); }
std::array<std::byte, 32> compute_body_digest(std::span<const std::byte> b) { return sha3_256(b); }
std::array<std::byte, 32> compute_entry_digest(std::span<const std::byte> b) { return sha3_256(b); }
std::array<std::byte, 32> compute_content_digest(std::span<const std::byte> d, std::span<const std::byte> game,
    std::span<const std::byte> major, bool include_game) {
    exact(d, 56, "content descriptor"); exact(major, 32, "major parameter digest");
    std::vector<std::byte> p; p.insert(p.end(), d.begin(), d.end());
    if (include_game) { exact(game, 32, "game digest"); p.insert(p.end(), game.begin(), game.end()); }
    p.insert(p.end(), major.begin(), major.end()); return sha3_256(p);
}
std::array<std::byte, 32> compute_header_digest(std::span<const std::byte> p, std::span<const std::byte> m) {
    exact(p, 64, "CNT header prefix"); exact(m, 128, "mount descriptor");
    std::array<std::byte, 192> x{}; std::copy(p.begin(), p.end(), x.begin()); std::copy(m.begin(), m.end(), x.begin() + 64); return sha3_256(x);
}
std::array<std::byte, 128> force_fih_relative_image_offset(std::span<const std::byte> d) {
    exact(d, 128, "mount descriptor"); std::array<std::byte, 128> x{}; std::copy(d.begin(), d.end(), x.begin());
    be64(std::span<std::byte>(x).subspan(0x10, 8), 0x10000); return x;
}
std::array<std::byte, 32> compute_package_digest(std::span<const std::byte> c) {
    if (c.size() < package_digest_region_size) throw std::invalid_argument("CNT is too small"); return sha3_256(c.first(package_digest_region_size));
}
std::optional<SblockDigestResult> compute_sblock_digest_from_image(std::span<const std::byte> image, std::size_t bs) {
    if (bs <= 0x10) return std::nullopt;
    for (std::size_t off = 0; off + bs <= image.size(); off += bs) {
        if (le64(image.subspan(off, 8)) == 2 && std::equal(sb_magic.begin(), sb_magic.end(), image.begin() + static_cast<std::ptrdiff_t>(off + 8)))
            return SblockDigestResult{off, compute_sblock_digest(image.subspan(off, bs))};
    }
    return std::nullopt;
}
} // namespace prosperopkg
