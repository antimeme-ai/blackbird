#pragma once

#include "blackbird/mp_client.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/value.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

enum class DoctorStatus : std::uint8_t { ok, info, warn, fail };

std::string_view doctor_status_name(DoctorStatus status) noexcept;

struct DoctorCheck {
  std::string id;
  std::string label;
  DoctorStatus status = DoctorStatus::ok;
  std::string summary;
  std::optional<std::string> hint;
  std::optional<std::uint64_t> rtt_ms;
  std::optional<std::int64_t> clock_skew_ms;

  bool operator==(const DoctorCheck &) const = default;
};

struct DoctorConfig {
  std::string current_version_string;
  std::filesystem::path install_prefix;
  std::filesystem::path online_state_dir;
  std::filesystem::path party_socket_path;
  mp::MpClientConfig mp_client_config;
  std::string relay_url = "https://relay.multiplayer.tech";
  // Optional loopback/test overrides for the relay TLS 1.3 health probe.
  // TLS SNI, X.509 hostname verification, and HTTP Host always derive from relay_url.
  std::string relay_connect_host;
  std::uint16_t relay_port = 0U;
  std::optional<std::filesystem::path> relay_ca_bundle_path;
  int relay_timeout_ms = 5000;
  std::string upgrade_base_url;
  bool offline = false;
  bool check_update = true;
  std::optional<std::filesystem::path> provider_auth_home;
};

struct DoctorReport {
  bool healthy = true;
  std::string target;
  std::string version;
  std::vector<DoctorCheck> checks;

  bool operator==(const DoctorReport &) const = default;
};

DoctorReport run_blackbird_doctor(const DoctorConfig &cfg);
std::string format_doctor_report_human(const DoctorReport &report);
Value doctor_report_to_json(const DoctorReport &report);

} // namespace blackbird
