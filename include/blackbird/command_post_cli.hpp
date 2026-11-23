#pragma once

#include <iosfwd>
#include <string_view>

namespace blackbird {

bool is_command_post_subcommand(std::string_view arg) noexcept;

int command_post_cli(int argc, char **argv, std::istream &in, std::ostream &out,
                     std::ostream &err);

} // namespace blackbird
