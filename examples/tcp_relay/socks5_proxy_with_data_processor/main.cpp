#include <boost/asio.hpp>
#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/server/handler_defs.hpp>
#include <iostream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy_with_simple_data_processor = builder.Build(
      socks5::server::TcpRelayDataProcessor{
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return [&](const char* data, size_t size,
                       const socks5::server::RelayDataSender& send) {
              std::cout << "Client to server: " << std::string_view{data, size}
                        << std::endl;
              send(data, size);
            };
          },
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return [&](const char* data, size_t size,
                       const socks5::server::RelayDataSender& send) {
              std::cout << "Server to client: " << std::string_view{data, size}
                        << std::endl;
              send(data, size);
            };
          }},
      nullptr);
  proxy_with_simple_data_processor.Run();
  proxy_with_simple_data_processor.Wait();
  return 0;
}