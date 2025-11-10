#include <server/handshake.hpp>
#include <utils/timeout.hpp>
#include <parsers/parsers.hpp>
#include <serializers/serializers.hpp>
#include <socks5/utils/type_traits.hpp>
#include <net/utils.hpp>
#include <common/proto_builders.hpp>

namespace socks5::server {

namespace {

// Size of first 4 fields of proto::Request.
constexpr size_t kRequestFirst4FieldsSize{4};
// Size of first 2 fields of proto::ClientGreeting.
constexpr size_t kClientGreetingFirst2FieldsSize{2};

tcp::acceptor MakeAcceptor(const asio::any_io_executor& executor,
                           const tcp::endpoint& ep) {
  tcp::acceptor acceptor{executor};
  acceptor.open(ep.protocol());
  acceptor.set_option(asio::socket_base::reuse_address(true));
  acceptor.bind(ep);
  acceptor.listen(1);
  return acceptor;
}

BoolAwait Validate(const tcp::endpoint& accepted_conn_ep,
                   const proto::Addr& target_srv_addr) {
  if (target_srv_addr.atyp != proto::AddrType::kAddrTypeDomainName) {
    const auto target_srv_ep = net::MakeEndpointFromIP<tcp>(target_srv_addr);
    co_return accepted_conn_ep == target_srv_ep;
  }
  auto [err, endpoints] =
      co_await net::MakeEndpointsFromDomain<tcp>(target_srv_addr);
  if (err) {
    co_return false;
  }
  tcp::resolver::iterator end;
  tcp::resolver::iterator it = *endpoints;
  while (it != end) {
    if (accepted_conn_ep == *it++) {
      co_return true;
    }
  }
  co_return false;
}

proto::Reply MakeReply(const boost::system::error_code& err,
                       const proto::Addr& addr) noexcept {
  const auto reply_rep = common::MakeReplyRep(err);
  return common::MakeReply(reply_rep, addr.atyp);
}

proto::Reply MakeReply(const tcp::endpoint& ep) noexcept {
  return common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);
}

}  // namespace

Handshake::Handshake(net::TcpConnection& connect, const Config& config,
                     const auth::server::UserAuthCb& user_auth_cb) noexcept
    : connect_{connect}, config_{config}, user_auth_cb_{user_auth_cb} {}

HandshakeResultOptAwait Handshake::Run() noexcept {
  try {
    auto handshake_res = co_await (
        RunImpl() ||
        utils::Timeout(std::chrono::seconds{config_.handshake_timeout}));
    if (handshake_res.index() == 1) {
      co_return std::nullopt;
    }
    co_return std::move(std::get<0>(handshake_res));
  } catch (const std::exception& ex) {
    SOCKS5_LOG(error, "Socks5 handshake exception. Client: {}. {}",
               net::ToString(connect_), ex.what());
    co_return std::nullopt;
  }
}

HandshakeResultOptAwait Handshake::RunImpl() noexcept {
  // Read the client greeting. Send a response with the selected
  // authentication method and authenticate using the selected method.
  // https://datatracker.ietf.org/doc/html/rfc1928#section-3,
  // https://datatracker.ietf.org/doc/html/rfc1929
  const auto auth_res = co_await Auth();
  if (!auth_res) {
    co_return std::nullopt;
  }

  // Read the request. Process CONNECT/BIND/UDP ASSOCIATE commands.
  // https://datatracker.ietf.org/doc/html/rfc1928#section-4,
  // https://datatracker.ietf.org/doc/html/rfc1928#section-6
  co_return co_await ProcessRequest();
}

BoolAwait Handshake::Auth() noexcept {
  const auto client_greeting = co_await ReadClientGreeting();
  if (!client_greeting) {
    co_return false;
  }
  const auto auth_method = ChoiceAuthMethod(*client_greeting);
  if (config_.enable_user_auth &&
      auth_method == proto::AuthMethod::kAuthMethodUser) {
    if (const auto err = co_await connect_.Send(
            serializers::Serialize(common::MakeServerChoice(auth_method)))) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
      co_return false;
    }
    auth::server::UserAuth user_auth{
        connect_, user_auth_cb_,
        auth::server::MakeConfig(config_.auth_username, config_.auth_password)};
    if (!co_await user_auth.Run()) {
      SOCKS5_LOG(debug, "Authentication failure. Client: {}",
                 net::ToString(connect_));
      co_return false;
    }
    co_return true;
  }
  if (const auto err = co_await connect_.Send(serializers::Serialize(
          common::MakeServerChoice(proto::AuthMethod::kAuthMethodNone)))) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return false;
  }
  co_return true;
}

ClientGreetingOptAwait Handshake::ReadClientGreeting() noexcept {
  ClientGreetingBuf buf;
  if (const auto err =
          co_await connect_.Read(buf, kClientGreetingFirst2FieldsSize)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  if (buf.Read<decltype(proto::ClientGreeting::ver)>() !=
      proto::Version::kVersionVer5) {
    co_return std::nullopt;
  }
  if (const auto err = co_await connect_.Read(
          buf, buf.Read<decltype(proto::ClientGreeting::nmethods)>())) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  co_return parsers::ParseClientGreeting(buf);
}

proto::AuthMethod Handshake::ChoiceAuthMethod(
    const proto::ClientGreeting& client_greeting) noexcept {
  for (uint8_t i = 0; i < client_greeting.nmethods; ++i) {
    if (client_greeting.methods[i] == proto::AuthMethod::kAuthMethodUser) {
      return proto::AuthMethod::kAuthMethodUser;
    }
  }
  return proto::AuthMethod::kAuthMethodNone;
}

HandshakeResultOptAwait Handshake::ProcessRequest() noexcept {
  try {
    const auto request = co_await ReadRequest();
    if (!request) {
      co_return std::nullopt;
    }
    co_return co_await ProcessCmd(*request);
  } catch (const std::exception& ex) {
    SOCKS5_LOG(debug, "Exception occurred while processing request. {}",
               ex.what());
    co_return std::nullopt;
  }
}

RequestOptAwait Handshake::ReadRequest() noexcept {
  RequestBuf buf;
  if (const auto err = co_await connect_.Read(buf, kRequestFirst4FieldsSize)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  if (buf.Read<decltype(proto::Request::ver)>() !=
      proto::Version::kVersionVer5) {
    co_return std::nullopt;
  }
  if (!co_await ReadAddr(buf,
                         static_cast<proto::AddrType>(
                             buf.ReadFromEnd<decltype(proto::Addr::atyp)>()))) {
    co_return std::nullopt;
  }
  co_return parsers::ParseRequest(buf);
}

HandshakeResultOptAwait Handshake::ProcessCmd(const proto::Request& request) {
  switch (request.cmd) {
    case proto::RequestCmd::kRequestCmdConnect: {
      auto res = co_await ProcessConnectCmd(request);
      if (!res) {
        SOCKS5_LOG(debug, "Handshake CONNECT CMD failure. Client: {}",
                   net::ToString(connect_));
      }
      co_return res;
    }
    case proto::RequestCmd::kRequestCmdUdpAssociate: {
      auto res = co_await ProcessUdpAssociateCmd(request);
      if (!res) {
        SOCKS5_LOG(debug, "Handshake UDP ASSOCIATE CMD failure. Client: {}",
                   net::ToString(connect_));
      }
      co_return res;
    }
    case proto::RequestCmd::kRequestCmdBind: {
      auto res = co_await ProcessBindCmd(request);
      if (!res) {
        SOCKS5_LOG(debug, "Handshake BIND CMD failure. Client: {}",
                   net::ToString(connect_));
      }
      co_return res;
    }
  }
  co_return co_await ProcessUnknownCmd(request);
}

HandshakeResultOptAwait Handshake::ProcessConnectCmd(
    const proto::Request& request) {
  auto [connect_err, socket] = co_await net::Connect(request.dst_addr);
  if (connect_err) {
    SOCKS5_LOG(debug, "Connect error. Client: {}, Server: {}. msg={}",
               net::ToString(connect_), common::ToString(request.dst_addr),
               connect_err.message());
  }
  if (config_.tcp_nodelay) {
    socket->set_option(tcp::no_delay{true});
  }
  const auto reply = connect_err ? MakeReply(connect_err, request.dst_addr)
                                 : MakeReply(socket->local_endpoint());
  const auto buf = serializers::Serialize(reply);
  if (const auto err = co_await connect_.Send(buf)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  if (connect_err) {
    co_return std::nullopt;
  }
  co_return ConnectCmdResult{std::move(*socket)};
}

HandshakeResultOptAwait Handshake::ProcessUdpAssociateCmd(
    const proto::Request& request) {
  const auto rep_and_addr_pair = MakeClientAddrForUDPRelay(request);
  if (!rep_and_addr_pair) {
    co_return std::nullopt;
  }
  if (rep_and_addr_pair->first != proto::ReplyRep::kReplyRepSuccess) {
    const auto buf = serializers::Serialize(common::MakeReply(
        rep_and_addr_pair->first, rep_and_addr_pair->second->atyp));
    co_await connect_.Send(buf);
    co_return std::nullopt;
  }
  auto proxy_socket = net::MakeOpenSocket<udp>(
      co_await asio::this_coro::executor, config_.listener_addr.first, 0);
  const auto buf = serializers::Serialize(common::MakeReply(
      rep_and_addr_pair->first, proxy_socket.local_endpoint()));
  if (const auto err = co_await connect_.Send(buf)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  co_return UdpAssociateCmdResult{std::move(proxy_socket),
                                  std::move(*rep_and_addr_pair->second)};
}

TcpEndpointOpt Handshake::GetLocalConnectEndpoint() noexcept {
  const auto [err, connect_ep] = connect_.LocalEndpoint();
  if (err) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    return std::nullopt;
  }
  return connect_ep;
}

BoolAwait Handshake::SendFirstBindCmdReply(
    const tcp::endpoint& acceptor_ep) noexcept {
  if (const auto err =
          co_await connect_.Send(serializers::Serialize(common::MakeReply(
              proto::ReplyRep::kReplyRepSuccess,
              acceptor_ep.address().is_v4() ? proto::AddrType::kAddrTypeIPv4
                                            : proto::AddrType::kAddrTypeIPv6,
              acceptor_ep.port())))) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return false;
  }
  co_return true;
}

HandshakeResultOptAwait Handshake::ProcessBindCmd(
    const proto::Request& request) {
  const auto connect_ep = GetLocalConnectEndpoint();
  if (!connect_ep) {
    co_return std::nullopt;
  }
  tcp::endpoint ep{connect_ep->address(), 0};
  auto acceptor = MakeAcceptor(co_await asio::this_coro::executor, ep);
  if (!co_await SendFirstBindCmdReply(acceptor.local_endpoint())) {
    co_return std::nullopt;
  }
  auto accept_res =
      co_await AcceptConnectForBindCmd(acceptor, request.dst_addr);
  if (!accept_res) {
    co_return std::nullopt;
  }
  if (const auto err =
          co_await connect_.Send(serializers::Serialize(common::MakeReply(
              proto::ReplyRep::kReplyRepSuccess, accept_res->second)))) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    co_return std::nullopt;
  }
  co_return BindCmdResult{std::move(accept_res->first)};
}

HandshakeResultOptAwait Handshake::ProcessUnknownCmd(
    const proto::Request& request) noexcept {
  co_await connect_.Send(serializers::Serialize(common::MakeReply(
      proto::ReplyRep::kReplyRepCommandNotSupported, request.dst_addr.atyp)));
  co_return std::nullopt;
}

detail::ClientAddrForUDPRelayOpt Handshake::MakeClientAddrForUDPRelay(
    const proto::Request& request) {
  switch (request.dst_addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      const auto addr = MakeClientIPv4AddrForUDPRelay(request);
      if (!addr) {
        return std::nullopt;
      }
      return std::make_pair(proto::ReplyRep::kReplyRepSuccess, std::move(addr));
    }
    case proto::AddrType::kAddrTypeIPv6: {
      const auto addr = MakeClientIPv6AddrForUDPRelay(request);
      if (!addr) {
        return std::nullopt;
      }
      return std::make_pair(proto::ReplyRep::kReplyRepSuccess, std::move(addr));
    }
  }
  return std::make_pair(proto::ReplyRep::kReplyRepAddrTypeNotSupported,
                        std::nullopt);
}

AddrOpt Handshake::MakeClientIPv4AddrForUDPRelay(
    const proto::Request& request) {
  if (!common::IsFilledWithZeros(request.dst_addr.addr.ipv4.addr)) {
    return request.dst_addr;
  }
  // If the Request.dst_addr is filled with zeros, the IP address of the TCP
  // socket is used. The port is set to 0, which means no port checking is
  // performed during UDP relaying.
  const auto [err, ep] = connect_.RemoteEndpoint();
  if (err) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    return std::nullopt;
  }
  return common::MakeAddr(ep->address(), 0);
}

AddrOpt Handshake::MakeClientIPv6AddrForUDPRelay(
    const proto::Request& request) {
  if (!common::IsFilledWithZeros(request.dst_addr.addr.ipv6.addr)) {
    return request.dst_addr;
  }
  // If the Request.dst_addr is filled with zeros, the IP address of the TCP
  // socket is used. The port is set to 0, which means no port checking is
  // performed during UDP relaying.
  const auto [err, ep] = connect_.RemoteEndpoint();
  if (err) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect_));
    return std::nullopt;
  }
  return common::MakeAddr(ep->address(), 0);
}

detail::AcceptedConnectForBindCmdOptAwait Handshake::AcceptConnectForBindCmd(
    tcp::acceptor& acceptor, const proto::Addr& target_srv_addr) {
  auto [err, socket] = co_await acceptor.async_accept(use_nothrow_awaitable);
  if (err) {
    SOCKS5_LOG(debug,
               "Processing bind cmd. Error accepting new connection. Excpected "
               "addr: {}. msg={}",
               common::ToString(target_srv_addr), err.message());
    co_return std::nullopt;
  }
  if (config_.tcp_nodelay) {
    socket.set_option(tcp::no_delay{true});
  }
  const auto ep = socket.remote_endpoint();
  if (config_.bind_validate_accepted_conn) {
    if (!co_await Validate(ep, target_srv_addr)) {
      SOCKS5_LOG(debug,
                 "Processing bind cmd. Accepted address validation error. "
                 "Expected addr: {}. Accepted addr: {}",
                 common::ToString(target_srv_addr), net::ToString<tcp>(ep));
      co_return std::nullopt;
    }
  }
  co_return std::make_pair(std::move(socket), std::move(ep));
}

}  // namespace socks5::server