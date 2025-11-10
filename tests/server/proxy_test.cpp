#include <gtest/gtest.h>
#include <server/proxy.hpp>
#include <server/handshake.hpp>

namespace socks5::server {

namespace {

class MockHandshakeConnectCmd final {
 public:
  MockHandshakeConnectCmd(
      net::TcpConnection& connect, const Config& config,
      const auth::server::UserAuthCb& user_auth_cb) noexcept {}

  HandshakeResultOptAwait Run() noexcept {
    co_return ConnectCmdResult{tcp::socket{io_context_}};
  }

 private:
  asio::io_context io_context_;
};

class MockHandshakeBindCmd final {
 public:
  MockHandshakeBindCmd(net::TcpConnection& connect, const Config& config,
                       const auth::server::UserAuthCb& user_auth_cb) noexcept {}

  HandshakeResultOptAwait Run() noexcept {
    co_return BindCmdResult{tcp::socket{io_context_}};
  }

 private:
  asio::io_context io_context_;
};

class MockHandshakeUdpAssociateCmd final {
 public:
  MockHandshakeUdpAssociateCmd(
      net::TcpConnection& connect, const Config& config,
      const auth::server::UserAuthCb& user_auth_cb) noexcept {}

  HandshakeResultOptAwait Run() noexcept {
    co_return UdpAssociateCmdResult{udp::socket{io_context_}, proto::Addr{}};
  }

 private:
  asio::io_context io_context_;
};

class MockHandshakeNullopt final {
 public:
  MockHandshakeNullopt(net::TcpConnection& connect, const Config& config,
                       const auth::server::UserAuthCb& user_auth_cb) noexcept {}

  HandshakeResultOptAwait Run() noexcept { co_return std::nullopt; }

 private:
  asio::io_context io_context_;
};

class MockTcpRelayHandler final {};
class MockUdpRelayHandler final {};

bool tcp_relay_called{false};

class MockTcpRelay final {
 public:
  using RelayHandler = MockTcpRelayHandler;

  MockTcpRelay(asio::io_context& io_context, net::TcpConnection client,
               net::TcpConnection server, const RelayHandler& handler,
               const Config& config, common::Metrics& metrics,
               const TcpRelayDataProcessor& tcp_data_processor) noexcept {}

  VoidAwait Run() noexcept {
    tcp_relay_called = true;
    co_return;
  }
};

bool udp_relay_called{false};

class MockUdpRelay final {
 public:
  using RelayHandler = MockUdpRelayHandler;

  MockUdpRelay(asio::io_context& io_context, net::TcpConnection client,
               net::UdpConnection proxy, proto::Addr client_addr,
               const RelayHandler& handler, const Config& config,
               common::Metrics& metrics,
               const UdpRelayDataProcessor& udp_data_processor) noexcept {}

  VoidAwait Run() noexcept {
    udp_relay_called = true;
    co_return;
  }
};

class ProxyTest : public testing::Test {
 public:
  ProxyTest()
      : connect_{tcp::socket{io_context_}, metrics_},
        tcp_data_processor_{MakeDefaultTcpRelayDataProcessor()},
        udp_data_processor_{MakeDefaultUdpRelayDataProcessor()} {
    tcp_relay_called = false;
    udp_relay_called = false;
  }

  asio::io_context io_context_;
  common::Metrics metrics_;
  net::TcpConnection connect_;
  Config config_;
  auth::server::UserAuthCb user_auth_cb_;
  TcpRelayDataProcessor tcp_data_processor_;
  UdpRelayDataProcessor udp_data_processor_;
  MockTcpRelayHandler tcp_relay_handler_;
  MockUdpRelayHandler udp_relay_handler_;
};

}  // namespace

TEST_F(ProxyTest, ProcessConnectCmd) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    Proxy<MockTcpRelay, MockUdpRelay, MockHandshakeConnectCmd> proxy{
        io_context_,
        std::move(connect_),
        tcp_relay_handler_,
        udp_relay_handler_,
        config_,
        metrics_,
        user_auth_cb_,
        tcp_data_processor_,
        udp_data_processor_};

    co_await proxy.Run();
    EXPECT_TRUE(tcp_relay_called);
    EXPECT_FALSE(udp_relay_called);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ProxyTest, ProcessBindCmd) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    Proxy<MockTcpRelay, MockUdpRelay, MockHandshakeUdpAssociateCmd> proxy{
        io_context_,
        std::move(connect_),
        tcp_relay_handler_,
        udp_relay_handler_,
        config_,
        metrics_,
        user_auth_cb_,
        tcp_data_processor_,
        udp_data_processor_};

    co_await proxy.Run();
    EXPECT_TRUE(udp_relay_called);
    EXPECT_FALSE(tcp_relay_called);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ProxyTest, ProcessUdpAssociateCmd) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    Proxy<MockTcpRelay, MockUdpRelay, MockHandshakeBindCmd> proxy{
        io_context_,
        std::move(connect_),
        tcp_relay_handler_,
        udp_relay_handler_,
        config_,
        metrics_,
        user_auth_cb_,
        tcp_data_processor_,
        udp_data_processor_};

    co_await proxy.Run();
    EXPECT_TRUE(tcp_relay_called);
    EXPECT_FALSE(udp_relay_called);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(ProxyTest, ProcessNullopt) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    Proxy<MockTcpRelay, MockUdpRelay, MockHandshakeNullopt> proxy{
        io_context_,
        std::move(connect_),
        tcp_relay_handler_,
        udp_relay_handler_,
        config_,
        metrics_,
        user_auth_cb_,
        tcp_data_processor_,
        udp_data_processor_};

    co_await proxy.Run();
    EXPECT_FALSE(tcp_relay_called);
    EXPECT_FALSE(udp_relay_called);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server