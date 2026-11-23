#pragma once

#include "blackbird/foundation.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace blackbird {

struct UpgradeTarget {
  std::string os;
  std::string arch;
  std::string triplet;
};

struct UpgradeConfig {
  std::string version = "latest";
  std::string base_url;
  std::filesystem::path prefix;
  bool force = false;
  bool no_ask = false;
  bool check_only = false;
  std::string current_version_string;
};

struct UpgradeCheckResult {
  std::string target;
  std::string current_version;
  std::string current_commit;
  std::string latest_version;
  std::string latest_commit;
  std::string asset_name;
  std::string expected_sha256;
  std::uint64_t expected_size_bytes = 0;
  bool update_available = false;
  std::string download_url;
};

enum class UpgradeStage : std::uint8_t {
  checking,
  prompt,
  downloading,
  verifying,
  extracting,
  smoke_testing,
  installing,
  complete
};

struct UpgradeProgress {
  UpgradeStage stage = UpgradeStage::checking;
  std::uint8_t step_index = 0;
  std::uint8_t step_total = 0;
  std::string message;
  std::uint64_t bytes_done = 0;
  std::uint64_t bytes_total = 0;
};

using UpgradeProgressCallback = std::function<void(const UpgradeProgress &)>;
using UpgradeConfirmCallback = std::function<bool(const UpgradeCheckResult &)>;

struct UpgradeResult {
  bool upgraded = false;
  bool already_up_to_date = false;
  bool cancelled_by_user = false;
  UpgradeCheckResult check;
  std::filesystem::path installed_binary;
  std::filesystem::path generation_dir;
  std::string installed_version_output;
};

Result<UpgradeTarget> detect_upgrade_target();
Result<bool> valid_upgrade_version(std::string_view version) noexcept;
Result<std::string> resolve_upgrade_base_url(const UpgradeConfig &cfg);
Result<UpgradeCheckResult>
check_for_upgrade(const UpgradeConfig &cfg,
                  const UpgradeProgressCallback &on_progress = {});
Result<UpgradeResult> perform_upgrade(const UpgradeConfig &cfg,
                                      const UpgradeProgressCallback &on_progress = {},
                                      const UpgradeConfirmCallback &confirm = {});
std::string format_upgrade_progress_line(const UpgradeProgress &p);
std::string format_upgrade_prompt_summary(const UpgradeCheckResult &check,
                                          const std::filesystem::path &prefix);

} // namespace blackbird
