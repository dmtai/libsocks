#include <auth/server/user_auth.hpp>
#include <net/utils.hpp>
#include <parsers/parsers.hpp>
#include <serializers/serializers.hpp>
#include <proto/proto.hpp>
#include <utils/logger.hpp>
#include <common/proto_builders.hpp>

namespace socks5::auth::server {

namespace {

constexpr size_t kUserAuthRequestFirst2FieldsSize{2};

}  // namespace

bool DefaultUserAuthCb(std::string_view username, std::string_view pass,
                       const Config& config) noexcept {
  return username == config.auth_username && pass == config.auth_password;
}

UserAuth::UserAuth(net::TcpConnection& connection,
                   const UserAuthCb& user_auth_cb,
                   const Config& config) noexcept
    : client_{connection}, user_auth_cb_{user_auth_cb}, config_{config} {}

UserAuthRequestOptAwait UserAuth::ReadUserAuthRequest() noexcept {
  UserAuthRequestBuf buf;
  if (const auto err =
          co_await client_.Read(buf, kUserAuthRequestFirst2FieldsSize)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, client_));
    co_return std::nullopt;
  }
  if (buf.Read<decltype(proto::UserAuthRequest::ver)>() !=
      proto::UserAuthVersion::kUserAuthVersionVer) {
    co_return std::nullopt;
  }
  const auto ulen = buf.Read<decltype(proto::UserAuthRequest::ulen)>();
  if (const auto err = co_await client_.Read(
          buf, ulen + sizeof(proto::UserAuthRequest::plen))) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, client_));
    co_return std::nullopt;
  }
  const auto plen = buf.ReadFromEnd<decltype(proto::UserAuthRequest::plen)>();
  if (const auto err = co_await client_.Read(buf, plen)) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*err, client_));
    co_return std::nullopt;
  }
  co_return parsers::ParseUserAuthRequest(buf);
}

BoolAwait UserAuth::Run() noexcept {
  try {
    const auto user_auth_req = co_await ReadUserAuthRequest();
    if (!user_auth_req) {
      co_return false;
    }
    if (!user_auth_cb_(std::string_view{reinterpret_cast<const char*>(
                                            user_auth_req->uname.data()),
                                        user_auth_req->ulen},
                       std::string_view{reinterpret_cast<const char*>(
                                            user_auth_req->passwd.data()),
                                        user_auth_req->plen},
                       config_)) {
      co_await client_.Send(serializers::Serialize(common::MakeUserAuthResponse(
          proto::UserAuthStatus::kUserAuthStatusFailure)));
      co_return false;
    }
    if (const auto err = co_await client_.Send(
            serializers::Serialize(common::MakeUserAuthResponse(
                proto::UserAuthStatus::kUserAuthStatusSuccess)))) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, client_));
      co_return false;
    }
    co_return true;
  } catch (const std::exception& ex) {
    SOCKS5_LOG(error, "UserAuth exception: {}", ex.what());
  }
}

}  // namespace socks5::auth::server