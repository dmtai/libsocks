#pragma once

#include <functional>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/common/asio.hpp>
#include <common/defs.hpp>
#include <socks5/auth/server/config.hpp>
#include <net/tcp_connection.hpp>

namespace socks5::auth::server {

using UserAuthCb = std::function<bool(
    std::string_view username, std::string_view pass, const Config& config)>;
using UserAuthCbPtr = std::shared_ptr<UserAuthCb>;

bool DefaultUserAuthCb(std::string_view username, std::string_view pass,
                       const Config& config) noexcept;

class UserAuth final : utils::NonCopyable {
 public:
  UserAuth(net::TcpConnection& connection, const UserAuthCb& user_auth_cb,
           const Config& config) noexcept;

  BoolAwait Run() noexcept;

 private:
  UserAuthRequestOptAwait ReadUserAuthRequest() noexcept;

  net::TcpConnection& client_;
  const UserAuthCb& user_auth_cb_;
  const Config& config_;
};

}  // namespace socks5::auth::server