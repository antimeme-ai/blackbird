#include "blackbird/context.hpp"
#include "blackbird/image_input.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/responses_provider.hpp"
#include <iostream>
using namespace blackbird;
namespace {
void check(bool value) {
  if (!value)
    throw Error{ErrorCode::corrupt};
}
template <class F> void refuse(F run) {
  bool denied = false;
  try {
    run();
  } catch (const Error &) {
    denied = true;
  }
  check(denied);
}
} // namespace
int main() {
  try {
    const std::string bytes{"\x89PNG\r\n\x1a\n\0f", 10};
    const auto original =
        Value::object({{"journal", Value{"11111111111111111111111111111111"}},
                       {"sequence", Value{Number{3}}}});
    const auto part = Value::object({{"type", Value{"input_image"}},
                                     {"image_original", original},
                                     {"detail", Value{"auto"}}});
    const auto item = Value::object({{"type", Value{"function_call_output"}},
                                     {"call_id", Value{"image-call"}},
                                     {"blackbird_output_parts", Value{true}},
                                     {"output", Value{Value::Array{part}}}});
    const auto native = Value::object({{"input", Value{Value::Array{item}}},
                                       {"store", Value{false}},
                                       {"stream", Value{true}}});
    const auto before = unwrap(encode_packet(native));
    unsigned loads = 0;
    const auto wire = materialize_provider_images(native, [&](const Value &ref) {
      check(ref == original);
      ++loads;
      return bytes;
    });
    check(loads == 1 && unwrap(encode_packet(native)) == before);
    const auto exported = export_registered_responses_request(wire, true);
    const auto &output =
        field(field(exported, "input").array()[0], "output").array()[0];
    check(!output.find("image_original") &&
          string_field(output, "image_url") ==
              "data:image/png;base64,iVBORw0KGgoAZg==");
    check(field(output, "detail") == Value{"auto"} &&
          !field(exported, "input").array()[0].find("blackbird_output_parts"));
    auto ambiguous = part;
    ambiguous.object().emplace_back("image_url",
                                    Value{"https://unselected.invalid/image.png"});
    auto bad = native;
    for (auto &[key, input] : bad.object())
      if (key == "input")
        for (auto &entry : input.array())
          for (auto &[name, value] : entry.object())
            if (name == "output")
              value = Value{Value::Array{ambiguous}};
    refuse([&] {
      (void)materialize_provider_images(bad, [&](const Value &) { return bytes; });
    });
    refuse([&] {
      (void)materialize_provider_images(
          native, [](const Value &) { return std::string{"not an image"}; });
    });
    refuse([&] { (void)image_original_result(bytes, "guessed-detail"); });
    const auto text = Value::object({{"input", Value{"ordinary text"}}});
    check(materialize_provider_images(text, [](const Value &) {
            throw Error{ErrorCode::corrupt};
            return std::string{};
          }) == text);
    std::string large = bytes;
    large.append(17 * 1024 * 1024, 'q');
    const auto large_wire =
        materialize_provider_images(native, [&](const Value &) { return large; });
    const auto &large_url = string_field(
        field(field(large_wire, "input").array()[0], "output").array()[0], "image_url");
    check(large_url.size() == 22 + ((large.size() + 2) / 3) * 4);
    std::cout << "Native image originals preserve context, exact byte encoding and "
                 "whole external payloads\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << error_name(e.code) << '\n';
    return 1;
  }
}
