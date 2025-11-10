#include <gtest/gtest.h>
#include <client/bind_handshake.hpp>
#include <net/tcp_connection.hpp>
#include <auth/client/user_auth.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/common/asio.hpp>
#include <chrono>
#include <utils/timeout.hpp>
#include <net/io.hpp>
#include <socks5/utils/buffer.hpp>
#include <common/defs.hpp>
#include <parsers/parsers.hpp>
#include <test_utils/assert_macro.hpp>
#include <common/proto_builders.hpp>
#include <serializers/serializers.hpp>
#include <socks5/utils/buffer.hpp>
#include <parsers/parsers.hpp>
#include <iostream>

namespace socks5::client {

namespace {

constexpr size_t kRequestFirst4FieldsSize{4};

class BindHandshakeTest : public ::testing::Test {
 protected:
  BindHandshakeTest()
      : client_acceptor_(io_context_),
        client_socket_(io_context_),
        server_socket_(io_context_) {
    client_acceptor_.open(tcp::v4());
    client_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    client_acceptor_.listen();
  }

  ~BindHandshakeTest() { io_context_.stop(); }

  void ConnectClient() {
    const auto server_endpoint = client_acceptor_.local_endpoint();
    client_socket_.async_connect(server_endpoint,
                                 [](auto err) { EXPECT_FALSE(err); });
    client_acceptor_.async_accept(server_socket_,
                                  [](auto err) { EXPECT_FALSE(err); });
  }

  asio::io_context io_context_;
  tcp::acceptor client_acceptor_;
  tcp::socket client_socket_;
  tcp::socket server_socket_;
};

tcp::acceptor MakeAcceptor(const asio::any_io_executor& executor,
                           const tcp::endpoint& ep) {
  tcp::acceptor acceptor{executor};
  acceptor.open(ep.protocol());
  acceptor.set_option(asio::socket_base::reuse_address(true));
  acceptor.bind(ep);
  acceptor.listen(1);
  return acceptor;
}

}  // namespace

TEST_F(BindHandshakeTest, Run) {
  ConnectClient();
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

  bool client_completed{false};
  auto client = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    BindHandshake handshake{client_socket_, inbound_connect_ep, auth_options};

    const auto auth_err = co_await handshake.Auth();
    CO_ASSERT_FALSE(auth_err);

    const auto req_err = co_await handshake.SendRequest();
    CO_ASSERT_FALSE(req_err);

    const auto [reply1_err, bind_ep] = co_await handshake.ProcessFirstReply();
    CO_ASSERT_FALSE(reply1_err);
    EXPECT_EQ(acceptor.local_endpoint(), *bind_ep);

    co_await test_socket.async_connect(*bind_ep, asio::use_awaitable);

    const auto [reply2_err, reply] = co_await handshake.ReadReply();
    CO_ASSERT_FALSE(reply2_err);
    const auto expected_addr = common::MakeAddr(inbound_connect_ep.address(),
                                                inbound_connect_ep.port());

    EXPECT_EQ(reply->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply->rsv, 0);
    EXPECT_EQ(reply->bnd_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(reply->bnd_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(reply->bnd_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    client_completed = true;
  };

  bool server_completed{false};
  auto server = [&]() -> asio::awaitable<void> {
    utils::StaticBuffer<1024> buf;
    co_await asio::async_read(server_socket_, asio::buffer(buf.BeginWrite(), 3),
                              asio::use_awaitable);
    buf.HasWritten(3);
    EXPECT_EQ(buf.Read<decltype(proto::ClientGreeting::ver)>(),
              proto::Version::kVersionVer5);
    EXPECT_EQ(buf.Read<decltype(proto::ClientGreeting::nmethods)>(), 1);
    EXPECT_EQ(buf.Read<uint8_t>(), proto::AuthMethod::kAuthMethodNone);

    const auto server_choice_buf = serializers::Serialize(
        common::MakeServerChoice(proto::AuthMethod::kAuthMethodNone));
    co_await asio::async_write(server_socket_,
                               asio::buffer(server_choice_buf.BeginRead(),
                                            server_choice_buf.ReadableBytes()),
                               asio::use_awaitable);
    RequestBuf request_buf;
    co_await asio::async_read(
        server_socket_,
        asio::buffer(request_buf.BeginWrite(),
                     kRequestFirst4FieldsSize + common::kIPv4AddrSize),
        asio::use_awaitable);
    request_buf.HasWritten(kRequestFirst4FieldsSize + common::kIPv4AddrSize);
    const auto request = parsers::ParseRequest(request_buf);

    common::Address target_server_addr{inbound_connect_ep};
    const auto expected_addr = target_server_addr.ToProtoAddr();

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdBind);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(request.dst_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(request.dst_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    const auto reply = common::MakeReply(proto::ReplyRep::kReplyRepSuccess,
                                         acceptor.local_endpoint());
    const auto reply_buf = serializers::Serialize(reply);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    auto accepted_socket = co_await acceptor.async_accept(asio::use_awaitable);

    const auto ep2 = accepted_socket.remote_endpoint();
    const auto reply2 =
        common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep2);
    const auto reply2_buf = serializers::Serialize(reply2);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply2_buf.BeginRead(), reply2_buf.ReadableBytes()),
        asio::use_awaitable);

    server_completed = true;
  };

  asio::co_spawn(io_context_, server, asio::detached);
  asio::co_spawn(io_context_, client, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
  EXPECT_TRUE(server_completed);
}

}  // namespace socks5::client