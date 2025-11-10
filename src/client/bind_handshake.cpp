#include <client/bind_handshake.hpp>
#include <proto/proto.hpp>
#include <serializers/serializers.hpp>
#include <net/io.hpp>
#include <parsers/parsers.hpp>
#include <socks5/error/error.hpp>
#include <net/utils.hpp>
#include <common/addr_utils.hpp>
#include <common/proto_builders.hpp>

namespace socks5::client {

namespace {

TcpEndpointOrErrorOpt MakeEndpointByAddrWithZeros(
    const proto::Addr& addr, const tcp::endpoint& target_server_ep) noexcept {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      if (common::IsFilledWithZeros(addr.addr.ipv4.addr)) {
        return std::make_pair(
            error::Error::kSucceeded,
            tcp::endpoint{target_server_ep.address(), addr.addr.ipv4.port});
      }
    }
    case proto::AddrType::kAddrTypeIPv6: {
      if (common::IsFilledWithZeros(addr.addr.ipv6.addr)) {
        return std::make_pair(
            error::Error::kSucceeded,
            tcp::endpoint{target_server_ep.address(), addr.addr.ipv6.port});
      }
    }
    case proto::AddrType::kAddrTypeDomainName: {
      if (common::IsFilledWithZeros(addr.addr.domain.addr)) {
        return std::make_pair(
            error::Error::kSucceeded,
            tcp::endpoint{target_server_ep.address(), addr.addr.domain.port});
      }
    }
  }
  return std::nullopt;
}

TcpEndpointOrErrorAwait MakeBindEndpoint(
    const proto::Addr& addr, const tcp::endpoint& inbound_connect_ep) noexcept {
  if (const auto res = MakeEndpointByAddrWithZeros(addr, inbound_connect_ep)) {
    co_return *res;
  }
  co_return co_await net::MakeEndpoint<tcp>(addr);
}

}  // namespace

BindHandshake::BindHandshake(
    tcp::socket& socket, const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options) noexcept
    : Handshake{socket, auth_options},
      inbound_connect_ep_{inbound_connect_ep} {}

// https://datatracker.ietf.org/doc/html/rfc1928#section-4
ErrorAwait BindHandshake::SendRequest() noexcept {
  const auto request = common::MakeRequest(proto::RequestCmd::kRequestCmdBind,
                                           inbound_connect_ep_);
  if (const auto err =
          co_await net::Send(socket_, serializers::Serialize(request))) {
    co_return err;
  }
  co_return error::Error::kSucceeded;
}

// https://datatracker.ietf.org/doc/html/rfc1928#section-6,
// https://www.openssh.com/txt/socks4.protocol
TcpEndpointOrErrorAwait BindHandshake::ProcessFirstReply() noexcept {
  const auto [err, reply] = co_await ReadReply();
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  if (reply->rep != proto::ReplyRep::kReplyRepSuccess) {
    co_return std::make_pair(error::MakeError(reply->rep), std::nullopt);
  }
  const auto [reply_err, bind_ep] =
      co_await MakeBindEndpoint(reply->bnd_addr, inbound_connect_ep_);
  if (reply_err) {
    co_return std::make_pair(std::move(reply_err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded, std::move(bind_ep));
}

TcpEndpointOrErrorAwait BindHandshake::ProcessSecondReply() noexcept {
  const auto [err, reply] = co_await ReadReply();
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  if (reply->rep != proto::ReplyRep::kReplyRepSuccess) {
    co_return std::make_pair(error::MakeError(reply->rep), std::nullopt);
  }
  const auto [accepted_ep_err, accepted_ep] =
      co_await net::MakeEndpoint<tcp>(reply->bnd_addr);
  if (accepted_ep_err) {
    co_return std::make_pair(std::move(accepted_ep_err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded, std::move(accepted_ep));
}

}  // namespace socks5::client