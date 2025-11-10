#include <gtest/gtest.h>
#include <socks5/common/asio.hpp>
#include <auth/server/user_auth.hpp>
#include <socks5/auth/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <socks5/common/metrics.hpp>
#include <memory>
#include <string>
#include <proto/proto.hpp>
#include <serializers/serializers.hpp>
#include <parsers/parsers.hpp>
#include <socks5/utils/buffer.hpp>
#include <utils/timeout.hpp>
#include <utils/string_utils.hpp>

namespace socks5::auth::server {

namespace {

constexpr std::string_view kServerIP{"127.0.0.1"};
constexpr unsigned short kServerPort{5555};

asio::awaitable<void> RunTestUserAuthServer(const UserAuthCb& user_auth_cb,
                                            const Config& config,
                                            bool is_request_valid) {
  try {
    tcp::acceptor acceptor{co_await asio::this_coro::executor,
                           {asio::ip::make_address("127.0.0.1"), kServerPort}};
    auto accepted_socket = co_await acceptor.async_accept(asio::use_awaitable);

    common::Metrics metrics;
    net::TcpConnection connect{std::move(accepted_socket), metrics};
    UserAuth user_auth{connect, user_auth_cb, config};
    const auto auth_res = co_await user_auth.Run();
    if (is_request_valid) {
      EXPECT_TRUE(auth_res);
    } else {
      EXPECT_FALSE(auth_res);
    }
  } catch (const std::exception& ex) {
    ADD_FAILURE() << ex.what();
  }
}

asio::awaitable<void> RunTestUserAuthClient(
    const Config& config, const UserAuthRequestBuf& auth_req_buf,
    bool is_response_valid) {
  try {
    tcp::socket socket{co_await asio::this_coro::executor};
    tcp::endpoint server_ep{asio::ip::make_address_v4(kServerIP), kServerPort};
    co_await socket.async_connect(server_ep, asio::use_awaitable);

    co_await asio::async_write(
        socket,
        asio::buffer(auth_req_buf.BeginRead(), auth_req_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<sizeof(proto::UserAuthResponse)> auth_response_buf;
    const auto recv_bytes = co_await asio::async_read(
        socket,
        asio::buffer(auth_response_buf.Begin(),
                     auth_response_buf.WritableBytes()),
        asio::use_awaitable);
    auth_response_buf.HasWritten(recv_bytes);
    const auto auth_response =
        parsers::ParseUserAuthResponse(auth_response_buf);
    EXPECT_TRUE(auth_response.ver ==
                proto::UserAuthVersion::kUserAuthVersionVer);
    if (is_response_valid) {
      EXPECT_TRUE(auth_response.status ==
                  proto::UserAuthStatus::kUserAuthStatusSuccess);
    } else {
      EXPECT_TRUE(auth_response.status ==
                  proto::UserAuthStatus::kUserAuthStatusFailure);
    }
  } catch (const std::exception& ex) {
    ADD_FAILURE() << ex.what();
  }
}

asio::awaitable<void> RunTestUserAuthClientWithInvalidRequest(
    const Config& config, const UserAuthRequestBuf& auth_req_buf) {
  try {
    tcp::socket socket{co_await asio::this_coro::executor};
    tcp::endpoint server_ep{asio::ip::make_address_v4(kServerIP), kServerPort};
    co_await socket.async_connect(server_ep, asio::use_awaitable);

    co_await asio::async_write(
        socket,
        asio::buffer(auth_req_buf.BeginRead(), auth_req_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<sizeof(proto::UserAuthResponse)> auth_response_buf;

    EXPECT_ANY_THROW(co_await asio::async_read(
        socket,
        asio::buffer(auth_response_buf.Begin(),
                     auth_response_buf.WritableBytes()),
        asio::use_awaitable));

  } catch (const std::exception& ex) {
    ADD_FAILURE() << ex.what();
  }
}

asio::awaitable<void> RunTestUserAuthClient(
    const Config& config, const proto::UserAuthRequest& auth_req,
    bool is_response_valid) {
  const auto auth_req_buf = serializers::Serialize(auth_req);
  co_await RunTestUserAuthClient(config, auth_req_buf, is_response_valid);
}

}  // namespace

TEST(ServerUserAuthTest, SuccessAuth) {
  Config config;
  config.auth_username = "user1";
  config.auth_password = "user1_password";
  UserAuthCb auth_cb = [](std::string_view username, std::string_view password,
                          const Config& config) {
    return username == config.auth_username && password == config.auth_password;
  };
  asio::io_context io_context{1};

  proto::UserAuthRequest auth_req;
  auth_req.ver = proto::UserAuthVersion::kUserAuthVersionVer;
  auth_req.ulen = config.auth_username.size();
  auth_req.uname = utils::ToArray<256>(config.auth_username);
  auth_req.plen = config.auth_password.size();
  auth_req.passwd = utils::ToArray<256>(config.auth_password);

  asio::co_spawn(io_context, RunTestUserAuthServer(auth_cb, config, true),
                 asio::detached);

  asio::co_spawn(io_context, RunTestUserAuthClient(config, auth_req, true),
                 asio::detached);

  io_context.run();
}

TEST(ServerUserAuthTest, WrongUsername) {
  Config config;
  config.auth_username = "user1";
  config.auth_password = "user1_password";

  UserAuthCb auth_cb = [](std::string_view username, std::string_view password,
                          const Config& config) {
    return username == config.auth_username && password == config.auth_password;
  };

  std::string_view username{"wrong_user"};
  std::string_view password{"user1_password"};

  proto::UserAuthRequest auth_req;
  auth_req.ver = proto::UserAuthVersion::kUserAuthVersionVer;
  auth_req.ulen = username.size();
  auth_req.uname = utils::ToArray<256>(username);
  auth_req.plen = password.size();
  auth_req.passwd = utils::ToArray<256>(password);

  asio::io_context io_context{1};

  asio::co_spawn(io_context, RunTestUserAuthServer(auth_cb, config, false),
                 asio::detached);
  asio::co_spawn(io_context, RunTestUserAuthClient(config, auth_req, false),
                 asio::detached);

  io_context.run();
}

TEST(ServerUserAuthTest, WrongPassword) {
  Config config;
  config.auth_username = "user1";
  config.auth_password = "user1_password";

  UserAuthCb auth_cb = [](std::string_view username, std::string_view password,
                          const Config& config) {
    return username == config.auth_username && password == config.auth_password;
  };

  std::string_view username{"user1"};
  std::string_view password{"wrong_password"};

  proto::UserAuthRequest auth_req;
  auth_req.ver = proto::UserAuthVersion::kUserAuthVersionVer;
  auth_req.ulen = username.size();
  auth_req.uname = utils::ToArray<256>(username);
  auth_req.plen = password.size();
  auth_req.passwd = utils::ToArray<256>(password);

  asio::io_context io_context{1};

  asio::co_spawn(io_context, RunTestUserAuthServer(auth_cb, config, false),
                 asio::detached);
  asio::co_spawn(io_context, RunTestUserAuthClient(config, auth_req, false),
                 asio::detached);

  io_context.run();
}

TEST(ServerUserAuthTest, EmptyCredentials) {
  Config config;
  config.auth_username = "user1";
  config.auth_password = "user1_password";

  UserAuthCb auth_cb = [](std::string_view username, std::string_view password,
                          const Config& config) {
    return username == config.auth_username && password == config.auth_password;
  };

  std::string_view username{""};
  std::string_view password{""};

  proto::UserAuthRequest auth_req;
  auth_req.ver = proto::UserAuthVersion::kUserAuthVersionVer;
  auth_req.ulen = username.size();
  auth_req.uname = utils::ToArray<256>(username);
  auth_req.plen = password.size();
  auth_req.passwd = utils::ToArray<256>(password);

  asio::io_context io_context{1};

  asio::co_spawn(io_context, RunTestUserAuthServer(auth_cb, config, false),
                 asio::detached);
  asio::co_spawn(io_context, RunTestUserAuthClient(config, auth_req, false),
                 asio::detached);

  io_context.run();
}

TEST(ServerUserAuthTest, InvalidAuthRequest) {
  Config config;
  config.auth_username = "user1";
  config.auth_password = "user1_password";

  UserAuthCb auth_cb = [](std::string_view username, std::string_view password,
                          const Config& config) {
    return username == config.auth_username && password == config.auth_password;
  };

  UserAuthRequestBuf auth_req_buf;
  std::memset(auth_req_buf.Begin(), 0, auth_req_buf.WritableBytes());
  auth_req_buf.HasWritten(auth_req_buf.WritableBytes());

  asio::io_context io_context{1};

  asio::co_spawn(io_context, RunTestUserAuthServer(auth_cb, config, false),
                 asio::detached);
  asio::co_spawn(io_context,
                 RunTestUserAuthClientWithInvalidRequest(config, auth_req_buf),
                 asio::detached);

  io_context.run();
}

}  // namespace socks5::auth::server