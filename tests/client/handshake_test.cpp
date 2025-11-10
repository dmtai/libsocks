#include <gtest/gtest.h>
#include <client/handshake.hpp>
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

namespace socks5::client {

namespace {

class ClientHandshakeTest : public ::testing::Test {
 protected:
  ClientHandshakeTest()
      : client_acceptor_(io_context_),
        client_socket_(io_context_),
        server_socket_(io_context_) {
    client_acceptor_.open(tcp::v4());
    client_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    client_acceptor_.listen();
  }

  ~ClientHandshakeTest() { io_context_.stop(); }

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

}  // namespace

TEST_F(ClientHandshakeTest, ReadIPv4Addr) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr =
        common::MakeAddr(asio::ip::make_address("192.168.1.1"), 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadIPv4Addr(read_addr_buf);
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadIPv6Addr) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr = common::MakeAddr(asio::ip::make_address("::1"), 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadIPv6Addr(read_addr_buf);
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadDomainAddr) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr = common::MakeAddr("example.com", 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadDomainAddr(read_addr_buf);
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadAddrDomain) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr = common::MakeAddr("example.com", 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadAddr(
        read_addr_buf,
        static_cast<proto::AddrType>(*read_addr_buf.BeginRead()));
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadAddrIPv4) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr =
        common::MakeAddr(asio::ip::make_address("192.168.1.1"), 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadAddr(
        read_addr_buf,
        static_cast<proto::AddrType>(*read_addr_buf.BeginRead()));
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadAddrIPv6) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto addr = common::MakeAddr(asio::ip::make_address("::1"), 8080);
    const auto addr_buf = serializers::Serialize(addr);
    co_await asio::async_write(
        server_socket_,
        asio::buffer(addr_buf.BeginRead(), addr_buf.ReadableBytes()),
        asio::use_awaitable);

    utils::StaticBuffer<1024> read_addr_buf;
    co_await asio::async_read(client_socket_,
                              asio::buffer(read_addr_buf.BeginWrite(), 1),
                              asio::use_awaitable);
    read_addr_buf.HasWritten(1);

    const auto err = co_await handshake.ReadAddr(
        read_addr_buf,
        static_cast<proto::AddrType>(*read_addr_buf.BeginRead()));
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(addr_buf.ReadableBytes() == read_addr_buf.ReadableBytes());
    EXPECT_TRUE(std::memcmp(addr_buf.BeginRead(), read_addr_buf.BeginRead(),
                            addr_buf.ReadableBytes()) == 0);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadServerChoice) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    const auto server_choice =
        common::MakeServerChoice(proto::AuthMethod::kAuthMethodNone);
    const auto server_choice_buf = serializers::Serialize(server_choice);
    co_await asio::async_write(server_socket_,
                               asio::buffer(server_choice_buf.BeginRead(),
                                            server_choice_buf.ReadableBytes()),
                               asio::use_awaitable);

    const auto [err, read_server_choice] =
        co_await handshake.ReadServerChoice();
    CO_ASSERT_FALSE(err);
    EXPECT_EQ(read_server_choice->ver, server_choice.ver);
    EXPECT_EQ(read_server_choice->method, server_choice.method);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, ReadReply) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    tcp::endpoint ep{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply = common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    const auto [err, read_reply] = co_await handshake.ReadReply();
    CO_ASSERT_FALSE(err);
    EXPECT_EQ(read_reply->ver, reply.ver);
    EXPECT_EQ(read_reply->rep, reply.rep);
    EXPECT_EQ(read_reply->rsv, reply.rsv);
    EXPECT_EQ(read_reply->bnd_addr.atyp, reply.bnd_addr.atyp);
    EXPECT_EQ(read_reply->bnd_addr.addr.ipv4.addr,
              reply.bnd_addr.addr.ipv4.addr);
    EXPECT_EQ(read_reply->bnd_addr.addr.ipv4.port,
              reply.bnd_addr.addr.ipv4.port);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ClientHandshakeTest, Auth) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    Handshake handshake{client_socket_, auth_options};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Auth(), asio::use_future);

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

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    EXPECT_EQ(result, error::Error::kSucceeded);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::client