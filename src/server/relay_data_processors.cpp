#include <server/relay_data_processors.hpp>

namespace socks5::server {

TcpRelayDataProcessor MakeDefaultTcpRelayDataProcessor() {
  static const auto data_proc_creator = [](const tcp::endpoint&,
                                           const tcp::endpoint&) {
    return TcpRelayDataProcessorCb{};
  };
  return TcpRelayDataProcessor{data_proc_creator, data_proc_creator};
}

UdpRelayDataProcessor MakeDefaultUdpRelayDataProcessor() {
  static const auto client_to_server = [](const udp::endpoint&) {
    return UdpRelayDataFromClientProcessorCb{};
  };
  static const auto server_to_client = [](const udp::endpoint&,
                                          const udp::endpoint&) {
    return UdpRelayDataProcessorCb{};
  };
  return UdpRelayDataProcessor{client_to_server, server_to_client};
}

}  // namespace socks5::server