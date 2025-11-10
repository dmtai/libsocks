#pragma once

#include <proto/proto.hpp>
#include <common/addr_utils.hpp>
#include <common/defs.hpp>

namespace socks5::parsers {

template <typename T>
proto::Request ParseRequest(T& buf) noexcept {
  buf.SeekToBegin();
  proto::Request request;
  buf.Read(request.ver);
  buf.Read(request.cmd);
  buf.Read(request.rsv);
  common::ReadAddr(buf, request.dst_addr);
  return request;
}

template <typename T>
proto::ClientGreeting ParseClientGreeting(T& buf) noexcept {
  buf.SeekToBegin();
  proto::ClientGreeting client_greeting;
  buf.Read(client_greeting.ver);
  buf.Read(client_greeting.nmethods);
  buf.Read(client_greeting.methods, client_greeting.nmethods);
  return client_greeting;
}

template <typename T>
proto::Datagram ParseDatagram(T& buf) noexcept {
  buf.SeekToBegin();
  proto::Datagram datagram;
  buf.Read(datagram.header.rsv);
  buf.Read(datagram.header.frag);
  common::ReadAddr(buf, datagram.header.addr);
  datagram.data.data = reinterpret_cast<uint8_t*>(buf.BeginRead());
  datagram.data.data_size = buf.ReadableBytes();
  return datagram;
}

template <typename T>
proto::UserAuthRequest ParseUserAuthRequest(T& buf) noexcept {
  buf.SeekToBegin();
  proto::UserAuthRequest user_auth_req{};
  buf.Read(user_auth_req.ver);
  buf.Read(user_auth_req.ulen);
  buf.Read(user_auth_req.uname, user_auth_req.ulen);
  buf.Read(user_auth_req.plen);
  buf.Read(user_auth_req.passwd, user_auth_req.plen);
  return user_auth_req;
}

template <typename T>
proto::ServerChoice ParseServerChoice(T& buf) noexcept {
  buf.SeekToBegin();
  proto::ServerChoice server_choice;
  buf.Read(server_choice.ver);
  buf.Read(server_choice.method);
  return server_choice;
}

template <typename T>
proto::Reply ParseReply(T& buf) noexcept {
  buf.SeekToBegin();
  proto::Reply reply;
  buf.Read(reply.ver);
  buf.Read(reply.rep);
  buf.Read(reply.rsv);
  common::ReadAddr(buf, reply.bnd_addr);
  return reply;
}

template <typename T>
proto::UserAuthResponse ParseUserAuthResponse(T& buf) noexcept {
  buf.SeekToBegin();
  proto::UserAuthResponse auth_response;
  buf.Read(auth_response.ver);
  buf.Read(auth_response.status);
  return auth_response;
}

template <typename T>
proto::Addr ParseAddr(T& buf) noexcept {
  buf.SeekToBegin();
  proto::Addr addr;
  common::ReadAddr(buf, addr);
  return addr;
}

}  // namespace socks5::parsers
