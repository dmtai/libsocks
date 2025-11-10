#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <client/handshake.hpp>
#include <socks5/client/defs.hpp>

namespace socks5::client {

class UdpAssociateHandshake final : public Handshake, utils::NonCopyable {
 public:
  UdpAssociateHandshake(tcp::socket& socket,
                        const auth::client::AuthOptions& auth_options) noexcept;
  UdpAssociateResultOrErrorAwait Run() noexcept;

 private:
  UdpAssociateResultOrErrorAwait ProcessRequest() noexcept;
  UdpEndpointOrErrorAwait ProcessConnectReply() noexcept;
};

}  // namespace socks5::client