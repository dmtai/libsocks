#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <common/defs.hpp>
#include <client/handshake.hpp>
#include <socks5/client/defs.hpp>

namespace socks5::client {

class BindHandshake final : public Handshake, utils::NonCopyable {
 public:
  BindHandshake(tcp::socket& socket, const tcp::endpoint& inbound_connect_ep,
                const auth::client::AuthOptions& auth_options) noexcept;
  ErrorAwait SendRequest() noexcept;
  TcpEndpointOrErrorAwait ProcessFirstReply() noexcept;
  TcpEndpointOrErrorAwait ProcessSecondReply() noexcept;

 private:
  const tcp::endpoint& inbound_connect_ep_;
};

}  // namespace socks5::client