#pragma once

#include <proto/proto.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/common/address.hpp>

namespace socks5::common {

proto::ServerChoice MakeServerChoice(
    const proto::AuthMethod auth_method) noexcept;
proto::ReplyRep MakeReplyRep(const boost::system::error_code& err) noexcept;
proto::Reply MakeReply(proto::ReplyRep reply_rep, uint8_t atyp,
                       unsigned short port = 0) noexcept;
proto::Addr MakeAddr(const asio::ip::address& asio_addr, unsigned short port);
proto::Addr MakeAddr(std::string_view domain, unsigned short port) noexcept;
proto::ClientGreeting MakeClientGreeting(
    const auth::client::AuthOptions& options) noexcept;
proto::UserAuthResponse MakeUserAuthResponse(
    proto::UserAuthStatus status) noexcept;
proto::UserAuthRequest MakeUserAuthRequest(
    const auth::client::UserAuthOptions& auth_options) noexcept;
proto::DatagramHeader MakeDatagramHeader(const udp::endpoint& ep);
proto::Datagram MakeDatagram(const udp::endpoint& ep, const char* data,
                             size_t size);
proto::Request MakeRequest(proto::RequestCmd cmd,
                           const Address& target_server_addr) noexcept;

template <typename Endpoint>
proto::Reply MakeReply(proto::ReplyRep reply_rep, Endpoint&& ep) {
  proto::Reply reply;
  reply.ver = proto::Version::kVersionVer5;
  reply.rep = reply_rep;
  reply.rsv = 0;
  reply.bnd_addr = common::MakeAddr(ep.address(), ep.port());
  return reply;
}

template <typename Buf>
proto::Datagram MakeDatagram(proto::Addr addr, Buf& buf) noexcept {
  proto::Datagram datagram;
  datagram.header.rsv = 0;
  datagram.header.frag = 0;
  datagram.header.addr = std::move(addr);
  datagram.data.data = reinterpret_cast<uint8_t*>(buf.Begin());
  datagram.data.data_size = buf.ReadableBytes();
  return datagram;
}

template <typename T>
proto::Request MakeRequest(proto::RequestCmd cmd,
                           const T& target_server_ep) noexcept {
  proto::Request request;
  request.ver = proto::Version::kVersionVer5;
  request.cmd = cmd;
  request.rsv = 0;
  request.dst_addr =
      common::MakeAddr(target_server_ep.address(), target_server_ep.port());
  return request;
}

}  // namespace socks5::common