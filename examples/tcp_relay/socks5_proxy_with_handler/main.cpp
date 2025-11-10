#include <algorithm>
#include <array>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/system/error_code.hpp>
#include <limits>
#include <socks5/common/asio.hpp>
#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/server/handler_defs.hpp>
#include <tuple>
#include <utility>
#include <variant>
#include <socks5/utils/watchdog.hpp>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

using namespace boost::asio::experimental::awaitable_operators;

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

constexpr std::size_t kRelayBufSize{16384};
// If there is no activity on the sockets during this time in seconds, terminate
// the relay.
constexpr std::size_t kWatchdogInterval{10};

socks5::VoidAwait Relay(tcp::socket& from, tcp::socket& to,
                        socks5::common::Metrics& metrics,
                        socks5::utils::Watchdog& watchdog) noexcept {
  std::array<char, kRelayBufSize> buffer{};
  for (;;) {
    watchdog.Update();
    auto [read_err, read_bytes] = co_await from.async_read_some(
        asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
    if (read_err) {
      co_return;
    }
    metrics.AddRecvBytes(read_bytes);

    watchdog.Update();
    const auto [sent_err, sent_bytes] =
        co_await asio::async_write(to, asio::buffer(buffer.data(), read_bytes),
                                   asio::as_tuple(asio::use_awaitable));
    if (sent_err) {
      co_return;
    }
    metrics.AddSentBytes(sent_bytes);
  }
}

socks5::VoidAwait CoroTcpRelayHandler(asio::io_context& io_context,
                                      socks5::tcp::socket client,
                                      socks5::tcp::socket server,
                                      const socks5::server::Config& config,
                                      socks5::common::Metrics& metrics) {
  try {
    // Tcp relay logic. Also see src/server/tcp_relay.cpp for an example.
    socks5::utils::Watchdog watchdog{co_await asio::this_coro::executor,
                                     kWatchdogInterval};
    co_await (Relay(client, server, metrics, watchdog) ||
              Relay(server, client, metrics, watchdog) || watchdog.Run());
  } catch (const std::exception&) {
    // Process exception.
  }
  co_return;
}

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy_with_tcp_relay_handler =
      builder.Build(CoroTcpRelayHandler, nullptr);
  proxy_with_tcp_relay_handler.Run();
  proxy_with_tcp_relay_handler.Wait();
  return 0;
}