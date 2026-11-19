#include "blackbird/image_input.hpp"
#include "blackbird/context.hpp"
#include <limits>
namespace blackbird {
std::string image_media_type(std::string_view bytes) {
  if (bytes.starts_with(std::string_view{"\x89PNG\r\n\x1a\n", 8}))
    return "image/png";
  if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xff &&
      static_cast<unsigned char>(bytes[1]) == 0xd8 &&
      static_cast<unsigned char>(bytes[2]) == 0xff)
    return "image/jpeg";
  if (bytes.starts_with("GIF87a") || bytes.starts_with("GIF89a"))
    return "image/gif";
  if (bytes.size() >= 12 && bytes.starts_with("RIFF") && bytes.substr(8, 4) == "WEBP")
    return "image/webp";
  throw Error{ErrorCode::unsupported};
}
Value image_original_result(std::string_view bytes, std::string detail) {
  if (detail != "auto" && detail != "low" && detail != "high" && detail != "original")
    throw Error{ErrorCode::invalid_range};
  return Value::object({{"mime_type", Value{image_media_type(bytes)}},
                        {"file_bytes", Value{Number{bytes.size()}}},
                        {"detail", Value{std::move(detail)}}});
}
namespace {
std::string base64(std::string_view bytes) {
  constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (bytes.size() > (std::numeric_limits<std::size_t>::max() / 4) * 3 - 2)
    throw Error{ErrorCode::capacity};
  std::string output;
  output.reserve(((bytes.size() + 2) / 3) * 4);
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    const auto a = static_cast<unsigned char>(bytes[i]);
    const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0U;
    const auto c = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0U;
    output += alphabet[a >> 2U];
    output += alphabet[((a & 3U) << 4U) | (b >> 4U)];
    output += i + 1 < bytes.size() ? alphabet[((b & 15U) << 2U) | (c >> 6U)] : '=';
    output += i + 2 < bytes.size() ? alphabet[c & 63U] : '=';
  }
  return output;
}
void parts(Value &content, const ImageOriginalLoader &load) {
  if (!std::holds_alternative<Value::Array>(content.value()))
    throw Error{ErrorCode::invalid_range};
  for (auto &part : content.array()) {
    const auto *type = part.find("type");
    if (!type || *type != Value{"input_image"})
      continue;
    const auto *original = part.find("image_original");
    if (!original)
      continue;
    if (part.find("image_url") || part.find("file_id"))
      throw Error{ErrorCode::invalid_range};
    for (const auto &[key, value] : part.object()) {
      (void)value;
      if (key != "type" && key != "image_original" && key != "detail")
        throw Error{ErrorCode::invalid_range};
    }
    const auto bytes = load(*original);
    const auto mime = image_media_type(bytes);
    Value::Object wire{
        {"type", Value{"input_image"}},
        {"image_url", Value{"data:" + mime + ";base64," + base64(bytes)}}};
    if (const auto *detail = part.find("detail")) {
      (void)image_original_result(bytes, string_field(part, "detail"));
      wire.emplace_back("detail", *detail);
    }
    part = Value::object(std::move(wire));
  }
}
} // namespace
Value materialize_provider_images(Value request, const ImageOriginalLoader &load) {
  if (!load)
    throw Error{ErrorCode::invalid_range};
  auto *input = request.find("input");
  if (!input)
    return request;
  // Value's const lookup protects aliases; detach the owned request before edits.
  for (auto &[key, value] : request.object())
    if (key == "input" && std::holds_alternative<Value::Array>(value.value())) {
      for (auto &item : value.array()) {
        const auto *type = item.find("type");
        const bool output = type && *type == Value{"function_call_output"};
        if (output && item.find("blackbird_output_parts") &&
            field(item, "blackbird_output_parts") == Value{true}) {
          for (auto &[name, content] : item.object())
            if (name == "output")
              parts(content, load);
        } else if ((!type || *type == Value{"message"}) && item.find("role")) {
          for (auto &[name, content] : item.object())
            if (name == "content" &&
                std::holds_alternative<Value::Array>(content.value()))
              parts(content, load);
        }
      }
    }
  return request;
}
} // namespace blackbird
