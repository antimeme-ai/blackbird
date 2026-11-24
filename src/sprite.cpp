#include "blackbird/sprite.hpp"
#include "blackbird/embedded_resources.hpp"
#include "blackbird/runtime_paths.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <span>
#include <stdexcept>
#include <string_view>
#include <unistd.h>

namespace blackbird {
namespace {
// Front three-quarter view traced from the operator's SR-71 reference.
// 24x24 bits occupy 12x6 Braille cells: square in a typical 1:2 terminal font.
constexpr std::array<std::string_view, 24> silhouette{
    "........................", "........................", "........................",
    "........................", "........................", "........##..............",
    "........##..............", "........##..............", "......##..#......#......",
    "......#####.##...#......", ".....##########.##......", ".......######..##.#.....",
    ".....##.#.#....####.....", "....#.##.#....#####.....", "...######.#####.#####...",
    "..##.##..#..#####.......", "..#.##.#####............", ".##...#.................",
    "######..................", "........................", "........................",
    "........................", "........................", "........................"};
static_assert([] {
  for (const auto row : silhouette)
    if (row.size() != blackbird_sprite_width * 2)
      return false;
  return true;
}());
std::array<std::string, blackbird_sprite_height> encode(unsigned flame) {
  constexpr unsigned dots[4][2]{{0, 3}, {1, 4}, {2, 5}, {6, 7}};
  std::array<std::string, blackbird_sprite_height> result;
  for (std::size_t y = 0; y < blackbird_sprite_height; ++y) {
    result[y].reserve(blackbird_sprite_width * 3);
    for (std::size_t x = 0; x < blackbird_sprite_width; ++x) {
      unsigned mask = 0;
      for (std::size_t dy = 0; dy < 4; ++dy)
        for (std::size_t dx = 0; dx < 2; ++dx) {
          const auto px = x * 2 + dx, py = y * 4 + dy;
          // Both jets trail up/right. No exhaust pixels or timer at idle.
          const bool exhaust =
              flame && ((px >= 10 && px < 10 + flame && py == 17 - px) ||
                        (px >= 18 && px < 18 + flame && py == 30 - px));
          if (silhouette[py][px] == '#' || exhaust)
            mask |= 1U << dots[dy][dx];
        }
      if (!mask)
        result[y] += ' ';
      else {
        const auto scalar = 0x2800U + mask;
        result[y] += static_cast<char>(0xe0U | (scalar >> 12));
        result[y] += static_cast<char>(0x80U | ((scalar >> 6) & 63));
        result[y] += static_cast<char>(0x80U | (scalar & 63));
      }
    }
  }
  return result;
}
} // namespace
const std::array<std::string, blackbird_sprite_height> &
blackbird_sprite(bool active, std::size_t phase) {
  static const std::array frames{encode(0), encode(2), encode(3), encode(4)};
  return frames[active ? 1 + phase % 3 : 0];
}
} // namespace blackbird

namespace blackbird {
namespace {
// Solid strokes and double-line shadow; every scalar here occupies one cell.
constexpr std::array<std::string_view, blackbird_lettering_height> lettering{
    "██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ██╗██████╗ ██████╗ ",
    "██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║██╔══██╗██╔══██╗",
    "██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║██████╔╝██║  ██║",
    "██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║██╔═██╗ ██║  ██║",
    "██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝██║██║  ██╗██████╔╝",
    "╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ "};
static_assert([] {
  for (const auto line : lettering) {
    std::size_t cells = 0;
    for (const char byte : line)
      cells += (static_cast<unsigned char>(byte) & 0xc0U) != 0x80U;
    if (cells != blackbird_lettering_width)
      return false;
  }
  return true;
}());
} // namespace
std::vector<std::string> blackbird_startup(std::size_t columns, std::size_t rows,
                                           bool mascot) {
  std::vector<std::string> result;
  if (!columns || !rows)
    return result;
  if (columns < blackbird_lettering_width || rows < blackbird_lettering_height) {
    result.emplace_back(std::string_view{"BLACKBIRD"}.substr(0, columns));
    return result;
  }
  (void)mascot; // Artwork is displayed directly by the terminal graphics path.
  for (const auto line : lettering)
    result.emplace_back(line);
  return result;
}
} // namespace blackbird

namespace blackbird {
namespace {
std::string_view setting(const char *name) {
  const auto *value = std::getenv(name);
  return value ? std::string_view{value} : std::string_view{};
}
std::string image_path() {
  const auto override_path = setting("BLACKBIRD_SPRITE_ASSET");
  return override_path.empty()
             ? runtime_resource({.relative = "assets/sr71.png",
                                 .development = BLACKBIRD_SPRITE_ASSET})
                   .string()
             : std::string{override_path};
}
std::string base64_encode(std::string_view bytes) {
  constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve((bytes.size() + 2) / 3 * 4);
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    const auto a = static_cast<unsigned char>(bytes[i]);
    const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0U;
    const auto c = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0U;
    result += alphabet[a >> 2];
    result += alphabet[((a & 3U) << 4) | (b >> 4)];
    result += i + 1 < bytes.size() ? alphabet[((b & 15U) << 2) | (c >> 6)] : '=';
    result += i + 2 < bytes.size() ? alphabet[c & 63U] : '=';
  }
  return result;
}
std::string encode_kitty_inline_png(std::span<const std::byte> png_bytes) {
  const std::string encoded = base64_encode(std::string_view{
      reinterpret_cast<const char *>(png_bytes.data()), png_bytes.size()});
  if (encoded.empty())
    return {};
  constexpr std::size_t kChunkSize = 4096U;
  std::string out;
  out.reserve(encoded.size() + (encoded.size() / kChunkSize + 1U) * 48U);
  std::size_t offset = 0U;
  bool first = true;
  while (offset < encoded.size()) {
    const std::size_t len = std::min(kChunkSize, encoded.size() - offset);
    const bool is_last = (offset + len >= encoded.size());
    if (first) {
      out += "\x1b_Ga=t,f=100,t=d,i=72171,q=2,";
      out += is_last ? "m=0;" : "m=1;";
      first = false;
    } else {
      out += is_last ? "\x1b_Gm=0;" : "\x1b_Gm=1;";
    }
    out.append(encoded.data() + offset, len);
    out += "\x1b\\";
    offset += len;
  }
  return out;
}
} // namespace
bool blackbird_graphics_available() {
  const auto mode = setting("BLACKBIRD_GRAPHICS");
  if (mode == "off")
    return false;
  if (mode != "kitty") {
    if (!mode.empty() || !setting("SSH_CONNECTION").empty() ||
        !setting("TMUX").empty() || !setting("STY").empty())
      return false;
    if (setting("TERM_PROGRAM") != "ghostty" && setting("TERM") != "xterm-ghostty" &&
        setting("TERM") != "xterm-kitty")
      return false;
  }
  const auto override_path = setting("BLACKBIRD_SPRITE_ASSET");
  if (!override_path.empty()) {
    return override_path.size() <= 3072 &&
           ::access(std::string{override_path}.c_str(), R_OK) == 0;
  }
  const auto path = image_path();
  if (!path.empty() && path.size() <= 3072 && ::access(path.c_str(), R_OK) == 0)
    return true;
  return !embedded_sr71_png().empty();
}
std::string blackbird_graphics_load_inline() {
  return encode_kitty_inline_png(embedded_sr71_png());
}
std::size_t blackbird_graphics_load_bound() noexcept {
  const auto override_path = setting("BLACKBIRD_SPRITE_ASSET");
  if (!override_path.empty())
    return 4096U;
  const auto path = image_path();
  if (!path.empty() && ::access(path.c_str(), R_OK) == 0)
    return 4096U;
  const std::size_t raw_bytes = embedded_sr71_png().size();
  if (raw_bytes == 0U)
    return 0U;
  const std::size_t encoded = ((raw_bytes + 2U) / 3U) * 4U;
  constexpr std::size_t kChunkSize = 4096U;
  const std::size_t chunks = (encoded + kChunkSize - 1U) / kChunkSize;
  return encoded + 64U + (chunks > 1U ? (chunks - 1U) * 16U : 0U);
}
std::string blackbird_graphics_load() {
  const auto override_path = setting("BLACKBIRD_SPRITE_ASSET");
  if (!override_path.empty()) {
    if (override_path.size() > 3072)
      throw std::length_error("graphics image path exceeds 3072 bytes");
    return "\x1b_Ga=t,f=100,t=f,i=72171,q=2;" + base64_encode(override_path) + "\x1b\\";
  }
  const auto path = image_path();
  if (!path.empty() && ::access(path.c_str(), R_OK) == 0) {
    if (path.size() > 3072)
      throw std::length_error("graphics image path exceeds 3072 bytes");
    return "\x1b_Ga=t,f=100,t=f,i=72171,q=2;" + base64_encode(path) + "\x1b\\";
  }
  return blackbird_graphics_load_inline();
}
std::string_view blackbird_graphics_erase(bool release) {
  return release ? "\x1b_Ga=d,d=I,i=72171,q=2;\x1b\\"
                 : "\x1b_Ga=d,d=i,i=72171,q=2;\x1b\\";
}
std::string blackbird_graphics_place(std::size_t row, std::size_t column,
                                     std::size_t columns, std::size_t rows) {
  if (!columns || !rows)
    return {};
  return "\x1b"
         "7\x1b[" +
         std::to_string(row + 1) + ";" + std::to_string(column + 1) +
         "H\x1b_Ga=p,i=72171,p=1,q=2,C=1,c=" + std::to_string(columns) +
         ",r=" + std::to_string(rows) +
         ";\x1b\\\x1b"
         "8";
}
} // namespace blackbird
