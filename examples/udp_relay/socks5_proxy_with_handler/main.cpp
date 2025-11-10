#include <boost/asio.hpp>
#include <socks5/server/handler_defs.hpp>
#include <socks5/server/server.hpp>
#include <socks5/server/server_builder.hpp>
#include <iostream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

socks5::VoidAwait CoroUdpRelayHandler(asio::io_context& io_context,
                                      socks5::tcp::socket client,
                                      socks5::udp::socket proxy,
                                      socks5::common::Address address,
                                      const socks5::server::Config& config,
                                      socks5::common::Metrics& metrics) {
  // Udp relay logic. See src/server/udp_relay.cpp for an example.
  co_return;
}

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy_with_udp_relay_handler =
      builder.Build(nullptr, CoroUdpRelayHandler);
  proxy_with_udp_relay_handler.Run();
  proxy_with_udp_relay_handler.Wait();
  return 0;
}