#pragma once

#include <socks5/utils/non_copyable.hpp>
#include <socks5/common/asio.hpp>
#include <common/defs.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/utils/status.hpp>

namespace socks5::auth::client {

using UserAuthResponseOrError = utils::ErrorOr<UserAuthResponseOpt>;
using UserAuthResponseOrErrorAwait = asio::awaitable<UserAuthResponseOrError>;

class UserAuth final : utils::NonCopyable {
 public:
  UserAuth(tcp::socket& socket, const UserAuthOptions& auth_options) noexcept;

  ErrorAwait Run() noexcept;

 private:
  UserAuthResponseOrErrorAwait ReadUserAuthResponse() noexcept;

  tcp::socket& socket_;
  const UserAuthOptions& auth_options_;
};

}  // namespace socks5::auth::client