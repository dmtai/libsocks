#include <client/handshake.hpp>
#include <proto/proto.hpp>
#include <serializers/serializers.hpp>
#include <net/io.hpp>
#include <parsers/parsers.hpp>
#include <socks5/error/error.hpp>
#include <auth/client/user_auth.hpp>
#include <common/proto_builders.hpp>

namespace socks5::client {

namespace {

constexpr size_t kServerChoiceSize{2};
constexpr size_t kReplyFirst4FieldsSize{4};

}  // namespace

Handshake::Handshake(tcp::socket& socket,
                     const auth::client::AuthOptions& auth_options) noexcept
    : socket_{socket}, auth_options_{auth_options} {}

ServerChoiceOrErrorAwait Handshake::ReadServerChoice() noexcept {
  ServerChoiceBuf buf;
  if (const auto err = co_await net::Read(socket_, buf, kServerChoiceSize)) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded,
                           parsers::ParseServerChoice(buf));
}

ReplyOrErrorAwait Handshake::ReadReply() noexcept {
  ReplyBuf buf;
  if (const auto err =
          co_await net::Read(socket_, buf, kReplyFirst4FieldsSize)) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  if (buf.Read<decltype(proto::Request::ver)>() !=
      proto::Version::kVersionVer5) {
    co_return std::make_pair(error::Error::kGeneralFailure, std::nullopt);
  }
  if (const auto err = co_await ReadAddr(
          buf, static_cast<proto::AddrType>(
                   buf.ReadFromEnd<decltype(proto::Addr::atyp)>()))) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded, parsers::ParseReply(buf));
}

ErrorAwait Handshake::Auth() noexcept {
  if (const auto err = co_await net::Send(
          socket_,
          serializers::Serialize(common::MakeClientGreeting(auth_options_)))) {
    co_return err;
  }
  const auto [err, server_choice] = co_await ReadServerChoice();
  if (err) {
    co_return err;
  }
  if (server_choice->method == proto::AuthMethod::kAuthMethodNone) {
    co_return error::Error::kSucceeded;
  } else if (server_choice->method == proto::AuthMethod::kAuthMethodUser) {
    const auto options = auth_options_.UserAuth();
    if (!options) {
      co_return error::Error::kGeneralFailure;
    }
    auth::client::UserAuth user_auth{socket_, *options};
    co_return co_await user_auth.Run();
  }
  co_return error::Error::kGeneralFailure;
}

}  // namespace socks5::client