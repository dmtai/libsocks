#include <serializers/serializers.hpp>
#include <common/addr_utils.hpp>

namespace socks5::serializers {

ServerChoiceBuf Serialize(const proto::ServerChoice& server_choice) noexcept {
  ServerChoiceBuf buf;
  buf.Append(server_choice.ver);
  buf.Append(server_choice.method);
  return buf;
}

ReplyBuf Serialize(const proto::Reply& reply) noexcept {
  ReplyBuf buf;
  buf.Append(reply.ver);
  buf.Append(reply.rep);
  buf.Append(reply.rsv);
  common::Append(buf, reply.bnd_addr);
  return buf;
}

UserAuthResponseBuf Serialize(
    const proto::UserAuthResponse& user_auth_resp) noexcept {
  UserAuthResponseBuf buf;
  buf.Append(user_auth_resp.ver);
  buf.Append(user_auth_resp.status);
  return buf;
}

ClientGreetingBuf Serialize(
    const proto::ClientGreeting& client_greeting) noexcept {
  ClientGreetingBuf buf;
  buf.Append(client_greeting.ver);
  buf.Append(client_greeting.nmethods);
  buf.Append(client_greeting.methods, client_greeting.nmethods);
  return buf;
}

RequestBuf Serialize(const proto::Request& request) noexcept {
  RequestBuf buf;
  buf.Append(request.ver);
  buf.Append(request.cmd);
  buf.Append(request.rsv);
  common::Append(buf, request.dst_addr);
  return buf;
}

UserAuthRequestBuf Serialize(
    const proto::UserAuthRequest& auth_request) noexcept {
  UserAuthRequestBuf buf;
  buf.Append(auth_request.ver);
  buf.Append(auth_request.ulen);
  buf.Append(auth_request.uname.data(), auth_request.ulen);
  buf.Append(auth_request.plen);
  buf.Append(auth_request.passwd.data(), auth_request.plen);
  return buf;
}

DatagramHeaderBuf Serialize(const proto::DatagramHeader& header) noexcept {
  DatagramHeaderBuf buf;
  buf.Append(header.rsv);
  buf.Append(header.frag);
  common::Append(buf, header.addr);
  return buf;
}

AddrBuf Serialize(const proto::Addr& addr) noexcept {
  AddrBuf buf;
  common::Append(buf, addr);
  return buf;
}

}  // namespace socks5::serializers