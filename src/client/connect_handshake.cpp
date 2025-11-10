#include <client/connect_handshake.hpp>
#include <serializers/serializers.hpp>
#include <net/io.hpp>
#include <parsers/parsers.hpp>
#include <socks5/error/error.hpp>
#include <common/proto_builders.hpp>

namespace socks5::client {

ConnectHandshake::ConnectHandshake(
    tcp::socket& socket, const common::Address& target_server_addr,
    const auth::client::AuthOptions& auth_options) noexcept
    : Handshake{socket, auth_options},
      target_server_addr_{target_server_addr} {}

ErrorAwait ConnectHandshake::ProcessRequest() noexcept {
  const auto request = common::MakeRequest(
      proto::RequestCmd::kRequestCmdConnect, target_server_addr_);
  if (const auto err =
          co_await net::Send(socket_, serializers::Serialize(request))) {
    co_return err;
  }
  const auto [err, reply] = co_await ReadReply();
  if (err) {
    co_return err;
  }
  co_return error::MakeError(reply->rep);
}

// Authentication and connection establishment with a socks5 proxy
// server for tcp relay.
ErrorAwait ConnectHandshake::Run() noexcept {
  if (const auto err = co_await Auth()) {
    co_return err;
  }
  if (const auto err = co_await ProcessRequest()) {
    co_return err;
  }
  co_return error::Error::kSucceeded;
}

}  // namespace socks5::client