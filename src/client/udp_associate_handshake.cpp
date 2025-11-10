#include <client/udp_associate_handshake.hpp>
#include <proto/proto.hpp>
#include <serializers/serializers.hpp>
#include <net/io.hpp>
#include <parsers/parsers.hpp>
#include <socks5/error/error.hpp>
#include <net/utils.hpp>
#include <common/addr_utils.hpp>
#include <common/proto_builders.hpp>

namespace socks5::client {

UdpAssociateHandshake::UdpAssociateHandshake(
    tcp::socket& socket, const auth::client::AuthOptions& auth_options) noexcept
    : Handshake{socket, auth_options} {}

UdpEndpointOrErrorAwait UdpAssociateHandshake::ProcessConnectReply() noexcept {
  const auto [reply_err, reply] = co_await ReadReply();
  if (reply_err) {
    co_return std::make_pair(std::move(reply_err), std::nullopt);
  }
  if (reply->rep != proto::ReplyRep::kReplyRepSuccess) {
    co_return std::make_pair(error::MakeError(reply->rep), std::nullopt);
  }
  auto [proxy_udp_ep_err, proxy_udp_ep] =
      co_await net::MakeEndpoint<udp>(reply->bnd_addr);
  if (proxy_udp_ep_err) {
    co_return std::make_pair(std::move(proxy_udp_ep_err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded, std::move(proxy_udp_ep));
}

UdpAssociateResultOrErrorAwait
UdpAssociateHandshake::ProcessRequest() noexcept {
  udp::socket udp_socket(socket_.get_executor(), udp::endpoint{udp::v4(), 0});
  boost::system::error_code err;
  const auto udp_socket_ep = udp_socket.local_endpoint(err);
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  if (const auto err = co_await net::Send(
          socket_,
          serializers::Serialize(common::MakeRequest(
              proto::RequestCmd::kRequestCmdUdpAssociate, udp_socket_ep)))) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  const auto [reply_err, proxy_udp_ep] = co_await ProcessConnectReply();
  if (reply_err) {
    co_return std::make_pair(std::move(reply_err), std::nullopt);
  }
  co_return std::make_pair(
      error::Error::kSucceeded,
      UdpAssociateResult{std::move(udp_socket), std::move(*proxy_udp_ep)});
}

// Authentication and connection establishment with a socks5 proxy
// server for udp relay.
UdpAssociateResultOrErrorAwait UdpAssociateHandshake::Run() noexcept {
  if (const auto err = co_await Auth()) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return co_await ProcessRequest();
}

}  // namespace socks5::client