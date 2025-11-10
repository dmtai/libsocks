#include <boost/asio.hpp>
#include <socks5/server/handler_defs.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/server/server.hpp>
#include <socks5/server/server_builder.hpp>
#include <iostream>
#include <string_view>
#include <utility>

namespace asio = boost::asio;
using udp = asio::ip::udp;

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

class ClientToServerDataProcessor final {
 public:
  ClientToServerDataProcessor(udp::endpoint client, std::string_view msg)
      : client_{std::move(client)}, num_{}, msg_{msg} {}

  void operator()(const char* data, size_t size, const udp::endpoint& server,
                  const socks5::server::RelayDataSender& send) {
    std::cout << num_ << ". " << msg_ << " (" << client_ << " -> " << server
              << "): " << std::string_view{data, size} << std::endl;
    ++num_;
    send(data, size);
  }

 private:
  udp::endpoint client_;
  size_t num_;
  std::string_view msg_;
};

class ServerToClientDataProcessor final {
 public:
  ServerToClientDataProcessor(udp::endpoint client, udp::endpoint server,
                              std::string_view msg)
      : client_{std::move(client)},
        server_{std::move(server)},
        num_{},
        msg_{msg} {}

  void operator()(const char* data, size_t size,
                  const socks5::server::RelayDataSender& send) {
    std::cout << num_ << ". " << msg_ << " (" << server_ << " -> " << client_
              << "): " << std::string_view{data, size} << std::endl;
    ++num_;
    send(data, size);
  }

 private:
  udp::endpoint client_;
  udp::endpoint server_;
  size_t num_;
  std::string_view msg_;
};

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy_with_stateful_data_processor = builder.Build(
      nullptr,
      socks5::server::UdpRelayDataProcessor{
          [](const udp::endpoint& client) {
            return ClientToServerDataProcessor{client, "Client to server"};
          },
          [](const udp::endpoint& client, const udp::endpoint& server) {
            return ServerToClientDataProcessor{client, server,
                                               "Server to client"};
          }});
  proxy_with_stateful_data_processor.Run();
  proxy_with_stateful_data_processor.Wait();
  return 0;
}