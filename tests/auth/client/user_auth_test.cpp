#include <gtest/gtest.h>
#include <socks5/common/asio.hpp>
#include <auth/server/user_auth.hpp>
#include <socks5/auth/server/config.hpp>
#include <auth/client/user_auth.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <net/tcp_connection.hpp>
#include <socks5/common/metrics.hpp>
#include <memory>
#include <string>
#include <proto/proto.hpp>
#include <serializers/serializers.hpp>
#include <parsers/parsers.hpp>
#include <socks5/utils/buffer.hpp>
#include <utils/timeout.hpp>
#include <common/proto_builders.hpp>
#include <common/defs.hpp>
#include <utils/string_utils.hpp>

namespace socks5::auth::client {

namespace {

constexpr std::string_view kServerIP{"127.0.0.1"};
constexpr unsigned short kServerPort{5555};

asio::awaitable<void> RunTestUserAuthClient(const UserAuthOptions& auth_options,
                                            bool is_request_valid) {
  try {
    tcp::socket socket{co_await asio::this_coro::executor};
    tcp::endpoint server_ep{asio::ip::make_address_v4(kServerIP), kServerPort};

    co_await socket.async_connect(server_ep, asio::use_awaitable);

    UserAuth user_auth{socket, auth_options};
    const auto err = co_await user_auth.Run();
    if (is_request_valid) {
      EXPECT_FALSE(err) << err.message();
    } else {
      EXPECT_TRUE(err);
    }
  } catch (const std::exception& ex) {
    ADD_FAILURE() << ex.what();
  }
}

asio::awaitable<void> RunTestUserAuthServer(const UserAuthOptions& auth_options,
                                            bool is_username_valid,
                                            bool is_password_valid) {
  try {
    tcp::acceptor acceptor{co_await asio::this_coro::executor,
                           {asio::ip::make_address("127.0.0.1"), kServerPort}};
    auto client_socket = co_await acceptor.async_accept(asio::use_awaitable);

    const auto expected_req_size =
        serializers::Serialize(common::MakeUserAuthRequest(auth_options))
            .ReadableBytes();
    UserAuthRequestBuf auth_req_buf;
    co_await asio::async_read(
        client_socket, asio::buffer(auth_req_buf.Begin(), expected_req_size),
        asio::use_awaitable);
    auth_req_buf.HasWritten(expected_req_size);

    const auto received_auth_req = parsers::ParseUserAuthRequest(auth_req_buf);
    const auto username =
        utils::ToSv(received_auth_req.uname, received_auth_req.ulen);
    const auto password =
        utils::ToSv(received_auth_req.passwd, received_auth_req.plen);
    if (is_username_valid) {
      EXPECT_TRUE(username == auth_options.username);
    } else {
      EXPECT_FALSE(username == auth_options.username);
    }
    if (is_password_valid) {
      EXPECT_TRUE(password == auth_options.password);
    } else {
      EXPECT_FALSE(password == auth_options.password);
    }

    proto::UserAuthResponse auth_reponse;
    auth_reponse.ver = proto::UserAuthVersion::kUserAuthVersionVer;
    if (is_username_valid && is_password_valid) {
      auth_reponse.status = proto::UserAuthStatus::kUserAuthStatusSuccess;
    } else {
      auth_reponse.status = proto::UserAuthStatus::kUserAuthStatusFailure;
    }
    const auto auth_response_buf = serializers::Serialize(auth_reponse);
    co_await asio::async_write(client_socket,
                               asio::buffer(auth_response_buf.Begin(),
                                            auth_response_buf.ReadableBytes()),
                               asio::use_awaitable);
  } catch (const std::exception& ex) {
    ADD_FAILURE() << ex.what();
  }
}

}  // namespace

TEST(ClientUserAuthTest, SuccessAuth) {
  asio::io_context io_context{1};

  auto auth_options =
      MakeAuthOptions().AddAuthMethod<auth::client::AuthMethod::kUser>(
          "user1", "user1_password");
  const auto user_auth_options = auth_options.UserAuth();
  ASSERT_TRUE(user_auth_options);

  asio::co_spawn(io_context,
                 RunTestUserAuthServer(*user_auth_options, true, true),
                 asio::detached);

  asio::co_spawn(io_context, RunTestUserAuthClient(*user_auth_options, true),
                 asio::detached);

  io_context.run();
}

TEST(ClientUserAuthTest, WrongUsername) {
  asio::io_context io_context{1};

  auto auth_options =
      MakeAuthOptions().AddAuthMethod<auth::client::AuthMethod::kUser>(
          "user1", "user1_password");
  const auto user_auth_options = auth_options.UserAuth();
  ASSERT_TRUE(user_auth_options);

  auto wrong_auth_options =
      MakeAuthOptions().AddAuthMethod<auth::client::AuthMethod::kUser>(
          "user2", "user1_password");
  const auto wrong_user_auth_options = wrong_auth_options.UserAuth();
  ASSERT_TRUE(wrong_user_auth_options);

  asio::co_spawn(io_context,
                 RunTestUserAuthServer(*wrong_user_auth_options, false, true),
                 asio::detached);

  asio::co_spawn(io_context, RunTestUserAuthClient(*user_auth_options, false),
                 asio::detached);

  io_context.run();
}

TEST(ClientUserAuthTest, WrongPassword) {
  asio::io_context io_context{1};

  auto auth_options =
      MakeAuthOptions().AddAuthMethod<auth::client::AuthMethod::kUser>(
          "user1", "user1_password");
  const auto user_auth_options = auth_options.UserAuth();
  ASSERT_TRUE(user_auth_options);

  auto wrong_auth_options =
      MakeAuthOptions().AddAuthMethod<auth::client::AuthMethod::kUser>(
          "user1", "user2_password");
  const auto wrong_user_auth_options = wrong_auth_options.UserAuth();
  ASSERT_TRUE(wrong_user_auth_options);

  asio::co_spawn(io_context,
                 RunTestUserAuthServer(*wrong_user_auth_options, true, false),
                 asio::detached);

  asio::co_spawn(io_context, RunTestUserAuthClient(*user_auth_options, false),
                 asio::detached);

  io_context.run();
}

}  // namespace socks5::auth::client