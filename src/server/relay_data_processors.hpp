#pragma once

#include <functional>
#include <socks5/server/config.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>

namespace socks5::server {

TcpRelayDataProcessor MakeDefaultTcpRelayDataProcessor();
UdpRelayDataProcessor MakeDefaultUdpRelayDataProcessor();

}  // namespace socks5::server