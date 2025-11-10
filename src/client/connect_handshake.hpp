#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <client/handshake.hpp>
#include <socks5/common/address.hpp>

namespace socks5::client {

class ConnectHandshake final : public Handshake, utils::NonCopyable {
 public:
  ConnectHandshake(tcp::socket& socket,
                   const common::Address& target_server_addr,
                   const auth::client::AuthOptions& auth_options) noexcept;
  ErrorAwait Run() noexcept;

 private:
  ErrorAwait ProcessRequest() noexcept;

  const common::Address& target_server_addr_;
};

}  // namespace socks5::client