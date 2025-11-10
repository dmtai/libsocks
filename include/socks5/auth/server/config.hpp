#pragma once

#include <string>
#include <socks5/common/api_macro.hpp>

namespace socks5::auth::server {

/**
 * @brief Socks5 proxy server authentication config.
 */
struct SOCKS5_API Config final {
  // Authentication username.
  std::string_view auth_username;
  // Authentication password.
  std::string_view auth_password;
};

SOCKS5_API Config MakeConfig(std::string_view auth_username,
                             std::string_view auth_password) noexcept;

}  // namespace socks5::auth::server