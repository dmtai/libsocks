#include <gtest/gtest.h>
#include <server/handshake.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <auth/server/user_auth.hpp>
#include <socks5/common/asio.hpp>
#include <thread>
#include <future>
#include <chrono>
#include <vector>
#include <utils/timeout.hpp>
#include <net/io.hpp>
#include <socks5/utils/buffer.hpp>
#include <common/defs.hpp>
#include <parsers/parsers.hpp>
#include <test_utils/assert_macro.hpp>
#include <iostream>

namespace socks5::server {

namespace {

constexpr size_t kServerChoiceSize{2};
constexpr size_t kReplyFirst4FieldsSize{4};

class HandshakeTest : public ::testing::Test {
 protected:
  HandshakeTest()
      : client_acceptor_(io_context_),
        client_acceptor_ipv6_(io_context_),
        client_socket_(io_context_),
        server_socket_(io_context_),
        connect_acceptor_{io_context_},
        connect_acceptor_ipv6_{io_context_},
        connect_socket_{io_context_} {
    client_acceptor_.open(tcp::v4());
    client_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    client_acceptor_.listen();

    client_acceptor_ipv6_.open(tcp::v6());
    client_acceptor_ipv6_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_ipv6_.bind(tcp::endpoint{asio::ip::make_address("::1"), 0});
    client_acceptor_ipv6_.listen();

    connect_acceptor_.open(tcp::v4());
    connect_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    connect_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 1234});
    connect_acceptor_.listen();

    connect_acceptor_ipv6_.open(tcp::v6());
    connect_acceptor_ipv6_.set_option(tcp::acceptor::reuse_address(true));
    connect_acceptor_ipv6_.bind(
        tcp::endpoint{asio::ip::make_address("::1"), 12345});
    connect_acceptor_ipv6_.listen();
  }

  ~HandshakeTest() { io_context_.stop(); }

  void ConnectClient() {
    const auto server_endpoint = client_acceptor_.local_endpoint();
    client_socket_.async_connect(server_endpoint,
                                 [](auto err) { EXPECT_FALSE(err); });
    client_acceptor_.async_accept(server_socket_,
                                  [](auto err) { EXPECT_FALSE(err); });
  }

  void ConnectIPv6Client() {
    const auto server_endpoint = client_acceptor_ipv6_.local_endpoint();
    client_socket_.async_connect(server_endpoint, [](auto) {});
    client_acceptor_ipv6_.accept(server_socket_);
  }

  void RunAcceptor() {
    connect_acceptor_.async_accept(connect_socket_, [&](auto ec) {
      if (!ec) {
        connect_accepted_ = true;
      }
    });
  }

  void RunIPv6Acceptor() {
    connect_acceptor_ipv6_.async_accept(connect_socket_, [&](auto ec) {
      if (!ec) {
        connect_accepted_ = true;
      }
    });
  }

  net::TcpConnection MakeConnection() {
    return net::TcpConnection(std::move(server_socket_), metrics_);
  }

  asio::awaitable<void> WriteClientData(const std::vector<uint8_t>& data) {
    co_await asio::async_write(client_socket_, asio::buffer(data, data.size()),
                               asio::use_awaitable);
  }

  asio::awaitable<std::vector<uint8_t>> ReadClientData(size_t size) {
    std::vector<uint8_t> buf(size);
    co_await asio::async_read(client_socket_, asio::buffer(buf.data(), size),
                              asio::use_awaitable);
    co_return buf;
  }

  template <typename Buffer>
  ErrorAwait ReadIPv4Addr(Buffer& buf) noexcept {
    co_return co_await net::Read(client_socket_, buf, common::kIPv4AddrSize);
  }

  template <typename Buffer>
  ErrorAwait ReadIPv6Addr(Buffer& buf) noexcept {
    co_return co_await net::Read(client_socket_, buf, common::kIPv6AddrSize);
  }

  template <typename Buffer>
  ErrorAwait ReadDomainAddr(Buffer& buf) noexcept {
    if (const auto err = co_await net::Read(
            client_socket_, buf, sizeof(decltype(proto::Domain::length)))) {
      co_return err;
    }
    if (const auto err = co_await net::Read(
            client_socket_, buf,
            buf.template ReadFromEnd<decltype(proto::Domain::length)>() +
                common::kAddrPortSize)) {
      co_return err;
    }
    co_return error::Error::kSucceeded;
  }

  template <typename Buffer>
  ErrorAwait ReadAddr(Buffer& buf, const proto::AddrType& atyp) noexcept {
    switch (atyp) {
      default: {
        co_return error::Error::kAddressTypeNotSupported;
      }
      case proto::AddrType::kAddrTypeIPv4: {
        co_return co_await ReadIPv4Addr(buf);
      }
      case proto::AddrType::kAddrTypeIPv6: {
        co_return co_await ReadIPv6Addr(buf);
      }
      case proto::AddrType::kAddrTypeDomainName: {
        co_return co_await ReadDomainAddr(buf);
      }
    }
  }

  asio::awaitable<
      std::pair<boost::system::error_code, std::optional<proto::Reply>>>
  ReadReply() noexcept {
    utils::StaticBuffer<sizeof(proto::Reply)> buf;
    if (const auto err =
            co_await net::Read(client_socket_, buf, kReplyFirst4FieldsSize)) {
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
    co_return std::make_pair(error::Error::kSucceeded,
                             parsers::ParseReply(buf));
  }

  asio::io_context io_context_;
  tcp::acceptor client_acceptor_;
  tcp::acceptor client_acceptor_ipv6_;
  tcp::socket client_socket_;
  tcp::socket server_socket_;
  tcp::socket connect_socket_;
  bool connect_accepted_{false};
  tcp::acceptor connect_acceptor_;
  tcp::acceptor connect_acceptor_ipv6_;
  common::Metrics metrics_;
};

template <typename T>
void VerifyIPv4Reply(const proto::Reply& reply, T&& ep) {
  EXPECT_EQ(reply.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(reply.rep, proto::ReplyRep::kReplyRepSuccess);
  EXPECT_EQ(reply.rsv, 0);
  EXPECT_EQ(reply.bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
  EXPECT_EQ(reply.bnd_addr.addr.ipv4.addr, (ep.address().to_v4().to_bytes()));
  EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                reply.bnd_addr.addr.ipv4.port),
            ep.port());
}

template <typename T>
void VerifyIPv6Reply(const proto::Reply& reply, T&& ep) {
  EXPECT_EQ(reply.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(reply.rep, proto::ReplyRep::kReplyRepSuccess);
  EXPECT_EQ(reply.rsv, 0);
  EXPECT_EQ(reply.bnd_addr.atyp, proto::AddrType::kAddrTypeIPv6);
  EXPECT_EQ(reply.bnd_addr.addr.ipv6.addr, (ep.address().to_v6().to_bytes()));
  EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                reply.bnd_addr.addr.ipv6.port),
            ep.port());
}

}  // namespace

TEST_F(HandshakeTest, FullSuccessfulIPv4Connect) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};

    RunAcceptor();
    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x01,             // CMD=CONNECT
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 1,  // ADDR=127.0.0.1
        0x04, 0xD2        // PORT=1234
    };
    co_await WriteClientData(request);
    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(connect_accepted_);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<ConnectCmdResult>(result.value()));
    const auto remote_ep =
        std::get<ConnectCmdResult>(*result).socket.remote_endpoint();
    EXPECT_EQ(remote_ep.address().to_v4().to_bytes(),
              (std::array<uint8_t, 4>{127, 0, 0, 1}));
    EXPECT_EQ(remote_ep.port(), 1234);

    VerifyIPv4Reply(
        *reply, std::get<ConnectCmdResult>(*result).socket.local_endpoint());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, FullSuccessfulIPv4UdpAssociate) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,                    // VER
        0x03,                    // CMD=UDP ASSOCIATE
        0x00,                    // RSV
        0x01,                    // ATYP=IPv4
        0x00, 0x00, 0x00, 0x00,  // ADDR=0.0.0.0
        0x00, 0x00               // PORT=0
    };
    co_await WriteClientData(request);

    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<UdpAssociateCmdResult>(result.value()));
    const auto& cmd_result = std::get<UdpAssociateCmdResult>(*result);
    EXPECT_EQ(cmd_result.client_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{127, 0, 0, 1}));
    EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                  cmd_result.client_addr.addr.ipv4.port),
              0);

    const auto local_ep = cmd_result.proxy_socket.local_endpoint();
    VerifyIPv4Reply(*reply, local_ep);
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, FullSuccessfulIPv4Bind) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x02,             // CMD=BIND
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 1,  // ADDR=127.0.0.1
        0x04, 0xD2        // PORT=1234
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);
    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{0, 0, 0, 0}));

    reply1->bnd_addr.addr.ipv4.addr = {127, 0, 0, 1};
    auto [connect_err, bind_socket] = co_await net::Connect(reply1->bnd_addr);

    CO_ASSERT_FALSE(connect_err);
    const auto [reply2_err, reply2] = co_await ReadReply();
    CO_ASSERT_FALSE(reply2_err);

    const auto local_ep = bind_socket->local_endpoint();
    VerifyIPv4Reply(*reply2, local_ep);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<BindCmdResult>(result.value()));
    const auto& cmd_result = std::get<BindCmdResult>(*result);
    EXPECT_EQ(bind_socket->remote_endpoint(),
              cmd_result.socket.local_endpoint());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, AuthTimeout) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.handshake_timeout = 1;
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};
    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);
    co_await utils::Timeout(1100);
    auto result = handshake_future.get();
    EXPECT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, UserAuthSuccess) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.enable_user_auth = true;
    const auth::server::UserAuthCb user_auth_cb =
        [](std::string_view username, std::string_view pass,
           const auth::server::Config&) {
          return username == "user" && pass == "pass";
        };
    Handshake handshake{conn, config, user_auth_cb};

    RunAcceptor();
    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData({0x05, 0x01, 0x02});

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x02}));

    std::vector<uint8_t> auth_request{
        0x01,                 // VER
        0x04,                 // ULEN=4
        'u',  's', 'e', 'r',  // UNAME
        0x04,                 // PLEN=4
        'p',  'a', 's', 's'   // PASSWD
    };
    co_await WriteClientData(auth_request);

    auto auth_response = co_await ReadClientData(2);
    EXPECT_EQ(auth_response, std::vector<uint8_t>({0x01, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x01,             // CMD=CONNECT
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 1,  // ADDR=127.0.0.1
        0x04, 0xD2        // PORT=1234
    };
    co_await WriteClientData(request);
    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(connect_accepted_);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(std::holds_alternative<ConnectCmdResult>(result.value()));
    const auto remote_ep =
        std::get<ConnectCmdResult>(*result).socket.remote_endpoint();
    EXPECT_EQ(remote_ep.address().to_v4().to_bytes(),
              (std::array<uint8_t, 4>{127, 0, 0, 1}));
    EXPECT_EQ(remote_ep.port(), 1234);

    const auto local_ep =
        std::get<ConnectCmdResult>(*result).socket.local_endpoint();
    VerifyIPv4Reply(*reply, local_ep);
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, UserAuthFailure) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.enable_user_auth = true;
    const auth::server::UserAuthCb user_auth_cb =
        [](std::string_view, std::string_view, const auth::server::Config&) {
          return false;
        };
    Handshake handshake{conn, config, user_auth_cb};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData({0x05, 0x01, 0x02});

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x02}));

    std::vector<uint8_t> auth_request{
        0x01,                 // VER
        0x04,                 // ULEN=4
        'u',  's', 'e', 'r',  // UNAME
        0x04,                 // PLEN=4
        'p',  'a', 's', 's'   // PASSWD
    };
    co_await WriteClientData(auth_request);

    auto auth_response = co_await ReadClientData(2);
    EXPECT_EQ(auth_response, std::vector<uint8_t>({0x01, 0x01}));

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    EXPECT_FALSE(result);
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, UnsupportedCommand) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0xFF,             // Invalid CMD
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 1,  // ADDR
        0x04, 0xD2        // PORT
    };
    co_await WriteClientData(request);
    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_FALSE(result);

    EXPECT_EQ(reply->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply->rep, proto::ReplyRep::kReplyRepCommandNotSupported);
    EXPECT_EQ(reply->rsv, 0);

    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, InvalidVersion) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x04, 0x01, 0x00});  // VER=4, NMETHODS=1, METHOD=0

    co_await utils::Timeout(100);
    auto result = handshake_future.get();
    CO_ASSERT_FALSE(result);

    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, IPv6AddressHandling) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    RunIPv6Acceptor();
    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,  // VER
        0x01,  // CMD=CONNECT
        0x00,  // RSV
        0x04,  // ATYP=IPv6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x39  // PORT=12345
    };
    co_await WriteClientData(request);
    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(connect_accepted_);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<ConnectCmdResult>(result.value()));
    const auto remote_ep =
        std::get<ConnectCmdResult>(*result).socket.remote_endpoint();
    EXPECT_EQ(remote_ep.address().to_v6().to_bytes(),
              (std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 1}));
    EXPECT_EQ(remote_ep.port(), 12345);

    const auto local_ep =
        std::get<ConnectCmdResult>(*result).socket.local_endpoint();
    VerifyIPv6Reply(*reply, local_ep);
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, DomainNameHandling) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    RunAcceptor();
    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,                                                     // VER
        0x01,                                                     // CMD=CONNECT
        0x00,                                                     // RSV
        0x03,                                                     // ATYP=DOMAIN
        0x09,                                                     // LENGTH=9
        'l',  'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x04, 0xD2  // PORT=1234
    };
    co_await WriteClientData(request);
    const auto [err, reply] = co_await ReadReply();
    CO_ASSERT_FALSE(err);
    CO_ASSERT_TRUE(connect_accepted_);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(std::holds_alternative<ConnectCmdResult>(result.value()));
    const auto remote_ep =
        std::get<ConnectCmdResult>(*result).socket.remote_endpoint();
    EXPECT_EQ(remote_ep.address().to_v4().to_bytes(),
              (std::array<uint8_t, 4>{127, 0, 0, 1}));
    EXPECT_EQ(remote_ep.port(), 1234);

    const auto local_ep =
        std::get<ConnectCmdResult>(*result).socket.local_endpoint();
    VerifyIPv4Reply(*reply, local_ep);
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindIPv4ValidationSuccess) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x02,             // CMD=BIND
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 1,  // ADDR=127.0.0.1
        0x30, 0x3A        // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{0, 0, 0, 0}));

    reply1->bnd_addr.addr.ipv4.addr = {127, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 12346};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    const auto [reply2_err, reply2] = co_await ReadReply();
    CO_ASSERT_FALSE(reply2_err);

    const auto local_ep = bind_socket->local_endpoint();
    VerifyIPv4Reply(*reply2, local_ep);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<BindCmdResult>(result.value()));
    const auto& cmd_result = std::get<BindCmdResult>(*result);
    EXPECT_EQ(bind_socket->remote_endpoint(),
              cmd_result.socket.local_endpoint());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindIPv4ValidationFaliure) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x02,             // CMD=BIND
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        127,  0,   0, 2,  // ADDR=127.0.0.2
        0x30, 0x3A        // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{0, 0, 0, 0}));

    reply1->bnd_addr.addr.ipv4.addr = {127, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 12346};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    EXPECT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindDomainValidationSuccess) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,                                                     // VER
        0x02,                                                     // CMD=BIND
        0x00,                                                     // RSV
        0x03,                                                     // ATYP=DOMAIN
        0x09,                                                     // LENGTH=9
        'l',  'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x30, 0x3A  // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{0, 0, 0, 0}));

    reply1->bnd_addr.addr.ipv4.addr = {127, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 12346};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    const auto [reply2_err, reply2] = co_await ReadReply();
    CO_ASSERT_FALSE(reply2_err);

    const auto local_ep = bind_socket->local_endpoint();
    VerifyIPv4Reply(*reply2, local_ep);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<BindCmdResult>(result.value()));
    const auto& cmd_result = std::get<BindCmdResult>(*result);
    EXPECT_EQ(bind_socket->remote_endpoint(),
              cmd_result.socket.local_endpoint());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindDomainValidationFailure) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,                                                     // VER
        0x02,                                                     // CMD=BIND
        0x00,                                                     // RSV
        0x03,                                                     // ATYP=DOMAIN
        0x09,                                                     // LENGTH=9
        'l',  'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x30, 0x3A  // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv4.addr,
              (std::array<uint8_t, 4>{0, 0, 0, 0}));

    reply1->bnd_addr.addr.ipv4.addr = {127, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"), 12347};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    EXPECT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{50000});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindIPv6ValidationSuccess) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    ConnectIPv6Client();
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,  // VER
        0x02,  // CMD=BIND
        0x00,  // RSV
        0x04,  // ATYP=IPv6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x3A  // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv6);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv6.addr,
              (std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0}));

    reply1->bnd_addr.addr.ipv6.addr = {0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address_v6("::1"), 12346};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    const auto [reply2_err, reply2] = co_await ReadReply();
    CO_ASSERT_FALSE(reply2_err);

    const auto local_ep = bind_socket->local_endpoint();
    VerifyIPv6Reply(*reply2, local_ep);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(std::holds_alternative<BindCmdResult>(result.value()));
    const auto& cmd_result = std::get<BindCmdResult>(*result);
    EXPECT_EQ(bind_socket->remote_endpoint(),
              cmd_result.socket.local_endpoint());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, BindIPv6ValidationFailure) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    ConnectIPv6Client();
    auto conn = MakeConnection();
    Config config{};
    config.bind_validate_accepted_conn = true;
    Handshake handshake{conn, config, [](auto, auto, auto) { return true; }};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,  // VER
        0x02,  // CMD=BIND
        0x00,  // RSV
        0x04,  // ATYP=IPv6
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x3A  // PORT=12346
    };
    co_await WriteClientData(request);

    auto [reply1_err, reply1] = co_await ReadReply();
    CO_ASSERT_FALSE(reply1_err);

    EXPECT_EQ(reply1->ver, proto::Version::kVersionVer5);
    EXPECT_EQ(reply1->rep, proto::ReplyRep::kReplyRepSuccess);
    EXPECT_EQ(reply1->rsv, 0);
    EXPECT_EQ(reply1->bnd_addr.atyp, proto::AddrType::kAddrTypeIPv6);
    EXPECT_EQ(reply1->bnd_addr.addr.ipv6.addr,
              (std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0}));

    reply1->bnd_addr.addr.ipv6.addr = {0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 1};
    tcp::endpoint ep{asio::ip::make_address_v6("::1"), 12346};
    auto [connect_err, bind_socket] =
        co_await net::Connect(reply1->bnd_addr, ep);
    CO_ASSERT_FALSE(connect_err);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    EXPECT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, ProcessRequestTimeout) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.handshake_timeout = 1;
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    co_await utils::Timeout(1100);
    auto result = handshake_future.get();
    CO_ASSERT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(HandshakeTest, ConnectToUnreachableTarget) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auto conn = MakeConnection();
    Config config{};
    config.handshake_timeout = 1;
    Handshake handshake{
        conn, config,
        auth::server::UserAuthCb{[](auto, auto, auto) { return true; }}};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    co_await WriteClientData(
        {0x05, 0x01, 0x00});  // VER=5, NMETHODS=1, METHOD=0

    const auto server_choice = co_await ReadClientData(2);
    EXPECT_EQ(server_choice, std::vector<uint8_t>({0x05, 0x00}));

    std::vector<uint8_t> request{
        0x05,             // VER
        0x01,             // CMD=CONNECT
        0x00,             // RSV
        0x01,             // ATYP=IPv4
        192,  0,   2, 1,  // ADDR=192.0.2.1
        0x04, 0xD2        // PORT=1234
    };
    co_await WriteClientData(request);

    co_await utils::Timeout(1100);
    auto result = handshake_future.get();
    CO_ASSERT_FALSE(result.has_value());
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server