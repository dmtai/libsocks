#pragma once

#include <variant>
#include <socks5/common/asio.hpp>
#include <proto/proto.hpp>
#include <utils/logger.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <common/addr_utils.hpp>
#include <common/defs.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <auth/server/user_auth.hpp>

namespace socks5::server {

struct ConnectCmdResult final {
  // Target server socket.
  tcp::socket socket;
};

struct UdpAssociateCmdResult final {
  // Proxy socket for reading client datagrams, which will then be relay.
  udp::socket proxy_socket;
  // The client address from which the proxy expects datagrams. If the port is
  // zero, then the client can have any port.
  proto::Addr client_addr;
};

struct BindCmdResult final {
  // Accepted socket from target server.
  tcp::socket socket;
};

using HandshakeResult =
    std::variant<ConnectCmdResult, UdpAssociateCmdResult, BindCmdResult>;
using HandshakeResultOpt = std::optional<HandshakeResult>;
using HandshakeResultOptAwait = asio::awaitable<HandshakeResultOpt>;

namespace detail {

using ClientAddrForUDPRelay = std::pair<proto::ReplyRep, AddrOpt>;
using ClientAddrForUDPRelayOpt = std::optional<ClientAddrForUDPRelay>;

using AcceptedConnectForBindCmd = std::pair<tcp::socket, tcp::endpoint>;
using AcceptedConnectForBindCmdOpt = std::optional<AcceptedConnectForBindCmd>;
using AcceptedConnectForBindCmdOptAwait =
    asio::awaitable<AcceptedConnectForBindCmdOpt>;

}  // namespace detail

class Handshake final : utils::NonCopyable {
 public:
  Handshake(net::TcpConnection& connect, const Config& config,
            const auth::server::UserAuthCb& user_auth_cb) noexcept;
  HandshakeResultOptAwait Run() noexcept;

 private:
  HandshakeResultOptAwait RunImpl() noexcept;
  BoolAwait Auth() noexcept;
  ClientGreetingOptAwait ReadClientGreeting() noexcept;
  proto::AuthMethod ChoiceAuthMethod(
      const proto::ClientGreeting& client_greeting) noexcept;
  RequestOptAwait ReadRequest() noexcept;
  HandshakeResultOptAwait ProcessRequest() noexcept;
  HandshakeResultOptAwait ProcessCmd(const proto::Request& request);
  HandshakeResultOptAwait ProcessConnectCmd(const proto::Request& request);
  HandshakeResultOptAwait ProcessUdpAssociateCmd(const proto::Request& request);
  HandshakeResultOptAwait ProcessBindCmd(const proto::Request& request);
  HandshakeResultOptAwait ProcessUnknownCmd(
      const proto::Request& request) noexcept;
  detail::ClientAddrForUDPRelayOpt MakeClientAddrForUDPRelay(
      const proto::Request& request);
  AddrOpt MakeClientIPv4AddrForUDPRelay(const proto::Request& request);
  AddrOpt MakeClientIPv6AddrForUDPRelay(const proto::Request& request);
  detail::AcceptedConnectForBindCmdOptAwait AcceptConnectForBindCmd(
      tcp::acceptor& acceptor, const proto::Addr& target_srv_addr);
  TcpEndpointOpt GetLocalConnectEndpoint() noexcept;
  BoolAwait SendFirstBindCmdReply(const tcp::endpoint& acceptor_ep) noexcept;

  template <typename Buffer>
  BoolAwait ReadIPv4Addr(Buffer& buf) noexcept {
    if (const auto err = co_await connect_.Read(buf, common::kIPv4AddrSize)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
      co_return false;
    }
    co_return true;
  }

  template <typename Buffer>
  BoolAwait ReadIPv6Addr(Buffer& buf) noexcept {
    if (const auto err = co_await connect_.Read(buf, common::kIPv6AddrSize)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
      co_return false;
    }
    co_return true;
  }

  template <typename Buffer>
  BoolAwait ReadDomainAddr(Buffer& buf) noexcept {
    if (const auto err = co_await connect_.Read(
            buf, sizeof(decltype(proto::Domain::length)))) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
      co_return false;
    }
    if (const auto err = co_await connect_.Read(
            buf, buf.template ReadFromEnd<decltype(proto::Domain::length)>() +
                     common::kAddrPortSize)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
      co_return false;
    }
    co_return true;
  }

  template <typename Buffer>
  BoolAwait ReadAddr(Buffer& buf, const proto::AddrType& atyp) noexcept {
    switch (atyp) {
      default: {
        SOCKS5_LOG(debug, "Reading address with unknown atyp. Client: {}",
                   net::ToString(connect_));
        co_return false;
      }
      case proto::AddrType::kAddrTypeIPv4: {
        co_return co_await ReadIPv4Addr(buf);
      }
      case proto::AddrType::kAddrTypeIPv6: {
        co_return co_await ReadIPv6Addr(buf);
      }
      case proto::AddrType::kAddrTypeDomainName: {
        co_return co_await ReadDomainAddr(buf);
      }
    }
  }

  net::TcpConnection& connect_;
  const Config& config_;
  const auth::server::UserAuthCb& user_auth_cb_;
};

}  // namespace socks5::server