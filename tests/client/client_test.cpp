#include <gtest/gtest.h>
#include <socks5/client/client.hpp>
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
#include <common/socks5_datagram_io.hpp>
#include <socks5/common/datagram_buffer.hpp>

namespace socks5::client {

namespace {

constexpr size_t kRequestFirst4FieldsSize{4};

class ClientTest : public ::testing::Test {
 protected:
  ClientTest()
      : client_acceptor_(io_context_),
        client_socket_(io_context_),
        server_socket_(io_context_) {
    client_acceptor_.open(tcp::v4());
    client_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    client_acceptor_.listen();
  }

  ~ClientTest() { io_context_.stop(); }

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

TEST_F(ClientTest, CoroAsyncConnectWithTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto connect_future =
        asio::co_spawn(io_context_,
                       AsyncConnect(client_socket_, proxy_server_ep,
                                    target_server_addr, auth_options, 5000),
                       asio::use_future);
    client_acceptor_.accept(server_socket_);

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
    const auto expected_addr = target_server_addr.ToProtoAddr();

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdConnect);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(request.dst_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(request.dst_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    tcp::endpoint ep2{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply =
        common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep2);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);
    auto result = connect_future.get();
    EXPECT_EQ(result, error::Error::kSucceeded);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncConnectWithTimeoutFailure) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto connect_future =
        asio::co_spawn(io_context_,
                       AsyncConnect(client_socket_, proxy_server_ep,
                                    target_server_addr, auth_options, 1),
                       asio::use_future);

    co_await utils::Timeout(50);
    auto result = connect_future.get();
    EXPECT_EQ(result, error::Error::kTimeoutExpired);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncConnect) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto connect_future =
        asio::co_spawn(io_context_,
                       AsyncConnect(client_socket_, proxy_server_ep,
                                    target_server_addr, auth_options),
                       asio::use_future);
    client_acceptor_.accept(server_socket_);

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
    const auto expected_addr = target_server_addr.ToProtoAddr();

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdConnect);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(request.dst_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(request.dst_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    tcp::endpoint ep2{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply =
        common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep2);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);
    auto result = connect_future.get();
    EXPECT_EQ(result, error::Error::kSucceeded);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, AsyncConnectWithTimeout) {
  bool completed{false};
  bool client_completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    AsyncConnect(client_socket_, proxy_server_ep, target_server_addr,
                 auth_options, 5000, [&](boost::system::error_code err) {
                   EXPECT_FALSE(err);
                   client_completed = true;
                 });

    client_acceptor_.accept(server_socket_);

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
    const auto expected_addr = target_server_addr.ToProtoAddr();

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdConnect);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(request.dst_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(request.dst_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    tcp::endpoint ep2{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply =
        common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep2);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, AsyncConnectWithTimeoutFailure) {
  bool completed{false};
  bool client_completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    AsyncConnect(client_socket_, proxy_server_ep, target_server_addr,
                 auth_options, 1, [&](boost::system::error_code err) {
                   EXPECT_TRUE(err);
                   client_completed = true;
                 });

    co_await utils::Timeout(50);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, AsyncConnect) {
  bool completed{false};
  bool client_completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
    common::Address target_server_addr{ep};

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    AsyncConnect(client_socket_, proxy_server_ep, target_server_addr,
                 auth_options, [&](boost::system::error_code err) {
                   EXPECT_FALSE(err);
                   client_completed = true;
                 });

    client_acceptor_.accept(server_socket_);

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
    const auto expected_addr = target_server_addr.ToProtoAddr();

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdConnect);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, expected_addr.atyp);
    EXPECT_EQ(request.dst_addr.addr.ipv4.addr, expected_addr.addr.ipv4.addr);
    EXPECT_EQ(request.dst_addr.addr.ipv4.port, expected_addr.addr.ipv4.port);

    tcp::endpoint ep2{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply =
        common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep2);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, CoroAsyncBindWithTimeout) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

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

  bool client_completed{false};
  auto client = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    client_acceptor_.async_accept([&](auto, tcp::socket sock) {
      server_socket_ = std::move(sock);
      asio::co_spawn(io_context_, server, asio::detached);
    });
    auto [ep_for_incoming_connect_err, ep_for_incoming_connect] =
        co_await FirstBindStep(client_socket_, proxy_server_ep,
                               inbound_connect_ep, auth_options, 5000);
    CO_ASSERT_FALSE(ep_for_incoming_connect_err);
    EXPECT_EQ(acceptor.local_endpoint(), *ep_for_incoming_connect);

    co_await test_socket.async_connect(*ep_for_incoming_connect,
                                       asio::use_awaitable);

    auto [accepted_ep_err, accepted_ep] =
        co_await SecondBindStep(client_socket_, 5000);
    CO_ASSERT_FALSE(accepted_ep_err);
    EXPECT_EQ(*accepted_ep, inbound_connect_ep);

    client_completed = true;
  };

  asio::co_spawn(io_context_, client, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
  EXPECT_TRUE(server_completed);
}

TEST_F(ClientTest, CoroAsyncBind) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

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

  bool client_completed{false};
  auto client = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    client_acceptor_.async_accept([&](auto, tcp::socket sock) {
      server_socket_ = std::move(sock);
      asio::co_spawn(io_context_, server, asio::detached);
    });
    auto [ep_for_incoming_connect_err, ep_for_incoming_connect] =
        co_await FirstBindStep(client_socket_, proxy_server_ep,
                               inbound_connect_ep, auth_options);
    CO_ASSERT_FALSE(ep_for_incoming_connect_err);
    EXPECT_EQ(acceptor.local_endpoint(), *ep_for_incoming_connect);

    co_await test_socket.async_connect(*ep_for_incoming_connect,
                                       asio::use_awaitable);

    auto [accepted_ep_err, accepted_ep] =
        co_await SecondBindStep(client_socket_);
    CO_ASSERT_FALSE(accepted_ep_err);
    EXPECT_EQ(*accepted_ep, inbound_connect_ep);

    client_completed = true;
  };

  asio::co_spawn(io_context_, client, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
  EXPECT_TRUE(server_completed);
}

TEST_F(ClientTest, FirstBindStepTimeout) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  bool client_completed{false};
  auto client = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto [ep_for_incoming_connect_err, ep_for_incoming_connect] =
        co_await FirstBindStep(client_socket_, proxy_server_ep,
                               inbound_connect_ep, auth_options, 1);
    EXPECT_EQ(ep_for_incoming_connect_err, error::Error::kTimeoutExpired);
    client_completed = true;
    io_context_.stop();
  };

  asio::co_spawn(io_context_, client, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, SecondBindStepTimeout) {
  ConnectClient();

  bool client_completed{false};
  auto client = [&]() -> asio::awaitable<void> {
    auto [accepted_ep_err, accepted_ep] =
        co_await SecondBindStep(client_socket_, 1);
    EXPECT_EQ(accepted_ep_err, error::Error::kTimeoutExpired);
    client_completed = true;
    io_context_.stop();
  };

  asio::co_spawn(io_context_, client, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, AsyncBindWithTimeout) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

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

  const auto proxy_server_ep = client_acceptor_.local_endpoint();
  client_acceptor_.async_accept([&](auto, tcp::socket sock) {
    server_socket_ = std::move(sock);
    asio::co_spawn(io_context_, server, asio::detached);
  });

  bool client_completed{false};
  auth::client::AuthOptions auth_options;
  auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
  AsyncBind(
      client_socket_, proxy_server_ep, inbound_connect_ep, auth_options, 5000,
      [&](const boost::system::error_code& err, const tcp::endpoint& bind_ep) {
        EXPECT_FALSE(err);
        EXPECT_EQ(acceptor.local_endpoint(), bind_ep);
        test_socket.async_connect(bind_ep, [](auto) {});
      },
      [&](const boost::system::error_code& err,
          const tcp::endpoint& accepted_ep) {
        EXPECT_FALSE(err);
        EXPECT_EQ(accepted_ep, inbound_connect_ep);
        client_completed = true;
      });

  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
  EXPECT_TRUE(server_completed);
}

TEST_F(ClientTest, AsyncBindWithTimeoutFailure) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

  const auto proxy_server_ep = client_acceptor_.local_endpoint();

  bool client_completed{false};
  auth::client::AuthOptions auth_options;
  auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
  AsyncBind(
      client_socket_, proxy_server_ep, inbound_connect_ep, auth_options, 1,
      [&](const boost::system::error_code& err, const tcp::endpoint& bind_ep) {
        EXPECT_TRUE(err);
        client_completed = true;
      },
      [&](const boost::system::error_code& err,
          const tcp::endpoint& accepted_ep) { client_completed = false; });

  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
}

TEST_F(ClientTest, AsyncBind) {
  tcp::socket test_socket{io_context_};
  test_socket.open(tcp::v4());
  test_socket.bind({asio::ip::make_address("127.0.0.1"), 0});
  auto inbound_connect_ep = test_socket.local_endpoint();

  tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = MakeAcceptor(io_context_.get_executor(), ep);

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

  const auto proxy_server_ep = client_acceptor_.local_endpoint();
  client_acceptor_.async_accept([&](auto, tcp::socket sock) {
    server_socket_ = std::move(sock);
    asio::co_spawn(io_context_, server, asio::detached);
  });

  bool client_completed{false};
  auth::client::AuthOptions auth_options;
  auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
  AsyncBind(
      client_socket_, proxy_server_ep, inbound_connect_ep, auth_options,
      [&](const boost::system::error_code& err, const tcp::endpoint& bind_ep) {
        EXPECT_FALSE(err);
        EXPECT_EQ(acceptor.local_endpoint(), bind_ep);
        test_socket.async_connect(bind_ep, [](auto) {});
      },
      [&](const boost::system::error_code& err,
          const tcp::endpoint& accepted_ep) {
        EXPECT_FALSE(err);
        EXPECT_EQ(accepted_ep, inbound_connect_ep);
        client_completed = true;
      });

  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(client_completed);
  EXPECT_TRUE(server_completed);
}

TEST_F(ClientTest, CoroAsyncUdpAssociateWithTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto udp_associate_future =
        asio::co_spawn(io_context_,
                       AsyncUdpAssociate(client_socket_, proxy_server_ep,
                                         auth_options, 50000000000),
                       asio::use_future);
    client_acceptor_.accept(server_socket_);

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

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdUdpAssociate);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, proto::AddrType::kAddrTypeIPv4);

    udp::endpoint ep{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply = common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);
    auto result = udp_associate_future.get();
    CO_ASSERT_FALSE(result.first);

    EXPECT_EQ(request.dst_addr.addr.ipv4.addr,
              (result.second->udp_socket.local_endpoint()
                   .address()
                   .to_v4()
                   .to_bytes()));
    EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                  request.dst_addr.addr.ipv4.port),
              result.second->udp_socket.local_endpoint().port());
    EXPECT_EQ(result.second->proxy_ep, ep);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncUdpAssociateWithTimeoutFailure) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto udp_associate_future = asio::co_spawn(
        io_context_,
        AsyncUdpAssociate(client_socket_, proxy_server_ep, auth_options, 1),
        asio::use_future);

    co_await utils::Timeout(50);
    auto result = udp_associate_future.get();
    CO_ASSERT_EQ(result.first, error::Error::kTimeoutExpired);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncUdpAssociate) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();

    const auto proxy_server_ep = client_acceptor_.local_endpoint();
    auto udp_associate_future = asio::co_spawn(
        io_context_,
        AsyncUdpAssociate(client_socket_, proxy_server_ep, auth_options),
        asio::use_future);
    client_acceptor_.accept(server_socket_);

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

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdUdpAssociate);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, proto::AddrType::kAddrTypeIPv4);

    udp::endpoint ep{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply = common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);
    auto result = udp_associate_future.get();
    CO_ASSERT_FALSE(result.first);

    EXPECT_EQ(request.dst_addr.addr.ipv4.addr,
              (result.second->udp_socket.local_endpoint()
                   .address()
                   .to_v4()
                   .to_bytes()));
    EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                  request.dst_addr.addr.ipv4.port),
              result.second->udp_socket.local_endpoint().port());
    EXPECT_EQ(result.second->proxy_ep, ep);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncSendToWithTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    udp::socket proxy_socket{co_await asio::this_coro::executor, udp::v4()};
    proxy_socket.bind(udp::endpoint{asio::ip::make_address("127.0.0.1"), 0});

    udp::socket test_socket{co_await asio::this_coro::executor, udp::v4()};
    test_socket.bind(udp::endpoint{asio::ip::make_address("127.0.0.1"), 0});

    common::Address target_server_addr{"example.com", 8080};
    const char* test_data{"hello"};
    const size_t data_size = sizeof(test_data) - 1;

    asio::co_spawn(io_context_,
                   AsyncSendTo(proxy_socket, test_socket.local_endpoint(),
                               target_server_addr, test_data, data_size, 5000),
                   asio::detached);

    DatagramBuf buf;
    udp::endpoint sender_ep;
    const auto recv_bytes = co_await test_socket.async_receive_from(
        asio::buffer(buf.BeginWrite(), buf.WritableBytes()), sender_ep,
        asio::use_awaitable);
    buf.HasWritten(recv_bytes);

    const auto dgrm = parsers::ParseDatagram(buf);
    CO_ASSERT_EQ(dgrm.data.data_size, data_size);
    EXPECT_EQ(dgrm.header.rsv, 0);
    EXPECT_EQ(dgrm.header.frag, 0);
    EXPECT_EQ(dgrm.header.addr.atyp, proto::AddrType::kAddrTypeDomainName);
    CO_ASSERT_EQ(dgrm.header.addr.addr.domain.length,
                 sizeof("example.com") - 1);
    EXPECT_TRUE(std::memcmp(dgrm.header.addr.addr.domain.addr.data(),
                            "example.com",
                            dgrm.header.addr.addr.domain.length) == 0);
    EXPECT_EQ(dgrm.header.addr.addr.domain.port,
              asio::detail::socket_ops::host_to_network_short(8080));

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncSendTo) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    udp::socket proxy_socket{co_await asio::this_coro::executor, udp::v4()};
    proxy_socket.bind(udp::endpoint{asio::ip::make_address("127.0.0.1"), 0});

    udp::socket test_socket{co_await asio::this_coro::executor, udp::v4()};
    test_socket.bind(udp::endpoint{asio::ip::make_address("127.0.0.1"), 0});

    common::Address target_server_addr{"example.com", 8080};
    const char* test_data{"hello"};
    const size_t data_size = sizeof(test_data) - 1;

    asio::co_spawn(io_context_,
                   AsyncSendTo(proxy_socket, test_socket.local_endpoint(),
                               target_server_addr, test_data, data_size),
                   asio::detached);

    DatagramBuf buf;
    udp::endpoint sender_ep;
    const auto recv_bytes = co_await test_socket.async_receive_from(
        asio::buffer(buf.BeginWrite(), buf.WritableBytes()), sender_ep,
        asio::use_awaitable);
    buf.HasWritten(recv_bytes);

    const auto dgrm = parsers::ParseDatagram(buf);
    CO_ASSERT_EQ(dgrm.data.data_size, data_size);
    EXPECT_EQ(dgrm.header.rsv, 0);
    EXPECT_EQ(dgrm.header.frag, 0);
    EXPECT_EQ(dgrm.header.addr.atyp, proto::AddrType::kAddrTypeDomainName);
    CO_ASSERT_EQ(dgrm.header.addr.addr.domain.length,
                 sizeof("example.com") - 1);
    EXPECT_TRUE(std::memcmp(dgrm.header.addr.addr.domain.addr.data(),
                            "example.com",
                            dgrm.header.addr.addr.domain.length) == 0);
    EXPECT_EQ(dgrm.header.addr.addr.domain.port,
              asio::detail::socket_ops::host_to_network_short(8080));

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncReceiveFromWithTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    udp::endpoint server_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12346};

    udp::endpoint proxy_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12347};
    udp::socket proxy_udp_socket{io_context_, proxy_udp_socket_ep};

    udp::endpoint client_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12348};
    udp::socket client_udp_socket{io_context_, client_udp_socket_ep};

    const auto addr = common::MakeAddr(server_udp_socket_ep.address(),
                                       server_udp_socket_ep.port());
    auto server_udp_socket_addr_buf = serializers::Serialize(addr);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf, data.data(), data.size());
    co_await proxy_udp_socket.async_send_to(dgrm_buffs, client_udp_socket_ep,
                                            asio::use_awaitable);

    udp::endpoint proxy_sender_ep;
    common::Address sender_addr;
    std::array<char, 1024> underlying_buf{};
    common::DatagramBuffer buf{underlying_buf.data(), underlying_buf.size()};
    const auto [err, recv_bytes] = co_await AsyncReceiveFrom(
        client_udp_socket, proxy_sender_ep, sender_addr, buf, 5000);
    CO_ASSERT_EQ(buf.DataSize(), data.size());
    EXPECT_TRUE(std::memcmp(buf.Data(), data.data(), buf.DataSize()) == 0);
    EXPECT_EQ(proxy_sender_ep, proxy_udp_socket_ep);
    EXPECT_EQ(sender_addr.ToEndpoint<udp>(), server_udp_socket_ep);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncReceiveFromWithTimeoutFailure) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    udp::endpoint server_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12346};

    udp::endpoint client_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12348};
    udp::socket client_udp_socket{io_context_, client_udp_socket_ep};

    const auto addr = common::MakeAddr(server_udp_socket_ep.address(),
                                       server_udp_socket_ep.port());
    auto server_udp_socket_addr_buf = serializers::Serialize(addr);

    udp::endpoint proxy_sender_ep;
    common::Address sender_addr;
    std::array<char, 1024> underlying_buf{};
    common::DatagramBuffer buf{underlying_buf.data(), underlying_buf.size()};
    const auto [err, recv_bytes] = co_await AsyncReceiveFrom(
        client_udp_socket, proxy_sender_ep, sender_addr, buf, 1);
    EXPECT_EQ(err, error::Error::kTimeoutExpired);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientTest, CoroAsyncReceiveFrom) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    udp::endpoint server_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12346};

    udp::endpoint proxy_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12347};
    udp::socket proxy_udp_socket{io_context_, proxy_udp_socket_ep};

    udp::endpoint client_udp_socket_ep{
        asio::ip::address::from_string("127.0.0.1"), 12348};
    udp::socket client_udp_socket{io_context_, client_udp_socket_ep};

    const auto addr = common::MakeAddr(server_udp_socket_ep.address(),
                                       server_udp_socket_ep.port());
    auto server_udp_socket_addr_buf = serializers::Serialize(addr);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf, data.data(), data.size());
    co_await proxy_udp_socket.async_send_to(dgrm_buffs, client_udp_socket_ep,
                                            asio::use_awaitable);

    udp::endpoint proxy_sender_ep;
    common::Address sender_addr;
    std::array<char, 1024> underlying_buf{};
    common::DatagramBuffer buf{underlying_buf.data(), underlying_buf.size()};
    const auto [err, recv_bytes] = co_await AsyncReceiveFrom(
        client_udp_socket, proxy_sender_ep, sender_addr, buf);
    CO_ASSERT_EQ(buf.DataSize(), data.size());
    EXPECT_TRUE(std::memcmp(buf.Data(), data.data(), buf.DataSize()) == 0);
    EXPECT_EQ(proxy_sender_ep, proxy_udp_socket_ep);
    EXPECT_EQ(sender_addr.ToEndpoint<udp>(), server_udp_socket_ep);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::client