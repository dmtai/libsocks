#include <common/proto_builders.hpp>

namespace socks5::common {

namespace {

proto::Addr MakeIPv4Addr(const asio::ip::address& asio_addr,
                         unsigned short port) {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeIPv4;
  addr.addr.ipv4.addr = asio_addr.to_v4().to_bytes();
  addr.addr.ipv4.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

proto::Addr MakeIPv6Addr(const asio::ip::address& asio_addr,
                         unsigned short port) {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeIPv6;
  addr.addr.ipv6.addr = asio_addr.to_v6().to_bytes();
  addr.addr.ipv6.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

}  // namespace

proto::Addr MakeAddr(const asio::ip::address& asio_addr, unsigned short port) {
  if (asio_addr.is_v4()) {
    return MakeIPv4Addr(asio_addr, port);
  } else {
    return MakeIPv6Addr(asio_addr, port);
  }
}

proto::Addr MakeAddr(std::string_view domain, unsigned short port) noexcept {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeDomainName;
  addr.addr.domain.length = domain.size();
  std::memcpy(addr.addr.domain.addr.data(), domain.data(),
              addr.addr.domain.addr.size());
  addr.addr.domain.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

proto::UserAuthResponse MakeUserAuthResponse(
    proto::UserAuthStatus status) noexcept {
  return {proto::UserAuthVersion::kUserAuthVersionVer, status};
}

proto::UserAuthRequest MakeUserAuthRequest(
    const auth::client::UserAuthOptions& auth_options) noexcept {
  proto::UserAuthRequest auth_request;
  auth_request.ver = proto::UserAuthVersion::kUserAuthVersionVer;
  auth_request.ulen = std::strlen(auth_options.username);
  std::memcpy(auth_request.uname.data(), auth_options.username,
              auth_request.ulen);
  auth_request.plen = std::strlen(auth_options.password);
  std::memcpy(auth_request.passwd.data(), auth_options.password,
              auth_request.plen);
  return auth_request;
}

proto::ClientGreeting MakeClientGreeting(
    const auth::client::AuthOptions& options) noexcept {
  proto::ClientGreeting client_greeting;
  client_greeting.ver = proto::Version::kVersionVer5;
  client_greeting.nmethods = options.Size();
  uint8_t i{};
  if (options.NoneAuth()) {
    client_greeting.methods[i++] = proto::AuthMethod::kAuthMethodNone;
  }
  if (options.UserAuth()) {
    client_greeting.methods[i] = proto::AuthMethod::kAuthMethodUser;
  }
  return client_greeting;
}

proto::Reply MakeReply(proto::ReplyRep reply_rep, uint8_t atyp,
                       unsigned short port) noexcept {
  proto::Reply reply{};
  reply.ver = proto::Version::kVersionVer5;
  reply.rep = reply_rep;
  switch (atyp) {
    case proto::AddrType::kAddrTypeIPv4:
    case proto::AddrType::kAddrTypeDomainName: {
      reply.bnd_addr.atyp = proto::AddrType::kAddrTypeIPv4;
      reply.bnd_addr.addr.ipv4.port =
          asio::detail::socket_ops::host_to_network_short(port);
      break;
    }
    case proto::AddrType::kAddrTypeIPv6: {
      reply.bnd_addr.atyp = proto::AddrType::kAddrTypeIPv6;
      reply.bnd_addr.addr.ipv6.port =
          asio::detail::socket_ops::host_to_network_short(port);
      break;
    }
  }
  return reply;
}

proto::ServerChoice MakeServerChoice(
    const proto::AuthMethod auth_method) noexcept {
  return {proto::Version::kVersionVer5, auth_method};
}

proto::ReplyRep MakeReplyRep(const boost::system::error_code& err) noexcept {
  if (!err) {
    return proto::ReplyRep::kReplyRepSuccess;
  }
  switch (err.value()) {
    case asio::error::connection_refused: {
      return proto::ReplyRep::kReplyRepConnectionRefused;
    }
    case asio::error::host_unreachable: {
      return proto::ReplyRep::kReplyRepHostUnreachable;
    }
    case asio::error::network_unreachable: {
      return proto::ReplyRep::kReplyRepNetworkUnreachable;
    }
  }
  return proto::ReplyRep::kReplyRepFail;
}

proto::DatagramHeader MakeDatagramHeader(const udp::endpoint& ep) {
  proto::DatagramHeader header;
  header.rsv = 0;
  header.frag = 0;
  header.addr = common::MakeAddr(ep.address(), ep.port());
  return header;
}

proto::Datagram MakeDatagram(const udp::endpoint& ep, const char* data,
                             size_t size) {
  proto::Datagram datagram;
  datagram.header = MakeDatagramHeader(ep);
  datagram.data.data = reinterpret_cast<uint8_t*>(const_cast<char*>(data));
  datagram.data.data_size = size;
  return datagram;
}

proto::Request MakeRequest(proto::RequestCmd cmd,
                           const Address& target_server_addr) noexcept {
  proto::Request request;
  request.ver = proto::Version::kVersionVer5;
  request.cmd = cmd;
  request.rsv = 0;
  request.dst_addr = target_server_addr.ToProtoAddr();
  return request;
}

}  // namespace socks5::common