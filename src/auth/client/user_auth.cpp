#include <auth/client/user_auth.hpp>
#include <net/utils.hpp>
#include <parsers/parsers.hpp>
#include <serializers/serializers.hpp>
#include <proto/proto.hpp>
#include <socks5/error/error.hpp>
#include <net/io.hpp>
#include <common/proto_builders.hpp>

namespace socks5::auth::client {

namespace {

constexpr size_t kUserAuthResponseSize{2};

}  // namespace

UserAuthResponseOrErrorAwait UserAuth::ReadUserAuthResponse() noexcept {
  UserAuthResponseBuf buf;
  if (const auto err =
          co_await net::Read(socket_, buf, kUserAuthResponseSize)) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded,
                           parsers::ParseUserAuthResponse(buf));
}

UserAuth::UserAuth(tcp::socket& socket,
                   const UserAuthOptions& auth_options) noexcept
    : socket_{socket}, auth_options_{auth_options} {}

ErrorAwait UserAuth::Run() noexcept {
  const auto auth_request = common::MakeUserAuthRequest(auth_options_);
  if (const auto err =
          co_await net::Send(socket_, serializers::Serialize(auth_request))) {
    co_return err;
  }
  const auto [err, auth_response] = co_await ReadUserAuthResponse();
  if (err) {
    co_return err;
  }
  if (auth_response->status != proto::UserAuthStatus::kUserAuthStatusSuccess) {
    co_return error::Error::kAuthFailure;
  }
  co_return error::Error::kSucceeded;
}

}  // namespace socks5::auth::client