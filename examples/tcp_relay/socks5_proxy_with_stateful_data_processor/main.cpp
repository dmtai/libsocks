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

class DataProcessor final {
 public:
  DataProcessor(tcp::endpoint from, tcp::endpoint to, std::string_view msg)
      : from_{std::move(from)}, to_{std::move(to)}, num_{}, msg_{msg} {}

  void operator()(const char* data, size_t size,
                  const socks5::server::RelayDataSender& send) {
    std::cout << num_ << ". " << msg_ << " " << std::string_view{data, size}
              << std::endl;
    ++num_;
    send(data, size);
  }

 private:
  tcp::endpoint from_;
  tcp::endpoint to_;
  size_t num_;
  std::string_view msg_;
};

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy_with_stateful_data_processor = builder.Build(
      socks5::server::TcpRelayDataProcessor{
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return DataProcessor{from, to, "Client to server"};
          },
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return DataProcessor{from, to, "Server to client"};
          }},
      nullptr);
  proxy_with_stateful_data_processor.Run();
  proxy_with_stateful_data_processor.Wait();
  return 0;
}