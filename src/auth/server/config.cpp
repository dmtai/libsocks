#include <socks5/auth/server/config.hpp>

namespace socks5::auth::server {

Config MakeConfig(std::string_view auth_username,
                  std::string_view auth_password) noexcept {
  return {auth_username, auth_password};
}

}  // namespace socks5::auth::server