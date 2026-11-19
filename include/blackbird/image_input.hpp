#pragma once
#include "blackbird/value.hpp"
#include <functional>
namespace blackbird {
// Native context retains only an immutable original reference. Binary encoding
// happens on the temporary provider-bound request, never in the retained core.
std::string image_media_type(std::string_view bytes);
Value image_original_result(std::string_view bytes, std::string detail = "auto");
using ImageOriginalLoader = std::function<std::string(const Value &)>;
Value materialize_provider_images(Value request, const ImageOriginalLoader &);
} // namespace blackbird
