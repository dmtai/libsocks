#include <gtest/gtest.h>
#include <server/listener.hpp>

namespace socks5::server {

namespace {

bool proxy_started{false};

class ListenerTest : public testing::Test {
 public:
  ListenerTest() { proxy_started = false; }
};

class MockTcpRelayHandler final {};
class MockUdpRelayHandler final {};

class MockProxy final {
 public:
  using TcpRelayHandler = MockTcpRelayHandler;
  using UdpRelayHandler = MockUdpRelayHandler;

  MockProxy(asio::io_context& io_context, net::TcpConnection connect,
            const TcpRelayHandler& tcp_relay_handler,
            const UdpRelayHandler& udp_relay_handler, const Config& config,
            common::Metrics& metrics,
            const auth::server::UserAuthCb& user_auth_cb,
            const TcpRelayDataProcessor& tcp_data_processor,
            const UdpRelayDataProcessor& udp_data_processor) noexcept {}

  VoidAwait Run() noexcept {
    proxy_started = true;
    co_return;
  }
};

}  // namespace

TEST_F(ListenerTest, AcceptConnect) {
  asio::io_context io_context;

  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    tcp::endpoint endpoint{asio::ip::address::from_string("127.0.0.1"), 7779};
    MockTcpRelayHandler test_tcp_relay_handler;
    MockUdpRelayHandler test_udp_relay_handler;
    Config config{};
    common::Metrics metrics;
    auth::server::UserAuthCb user_auth_cb;
    auto tcp_data_processor = MakeDefaultTcpRelayDataProcessor();
    auto udp_data_processor = MakeDefaultUdpRelayDataProcessor();

    auto listener = std::make_shared<Listener<MockProxy>>(
        io_context, endpoint, test_tcp_relay_handler, test_udp_relay_handler,
        config, metrics, user_auth_cb, tcp_data_processor, udp_data_processor);
    listener->Run();

    tcp::socket client_socket{io_context};
    co_await client_socket.async_connect(endpoint, asio::use_awaitable);
    co_await utils::Timeout(50);
    EXPECT_TRUE(proxy_started);

    io_context.stop();
    completed = true;
  };

  asio::co_spawn(io_context, main, asio::detached);
  io_context.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server