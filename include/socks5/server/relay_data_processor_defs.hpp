#pragma once

#include <functional>
#include <socks5/server/config.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/api_macro.hpp>

namespace socks5::server {

using RelayData = std::pair<const char*, size_t>;

/**
 * @brief A callback that will asynchronously send data to the network.
 *
 * @param data pointer to data to send.
 * @param size data size.
 */
using RelayDataSender = std::function<void(const char* data, size_t size)>;

/**
 * @brief A callback that processes TCP data relayed through the socks5 proxy
 * server.
 *
 * @param data pointer to relayed data.
 * @param size data size.
 * @param send callback that will asynchronously send data to the network.
 */
using TcpRelayDataProcessorCb = std::function<void(
    const char* data, size_t size, const RelayDataSender& send)>;

/**
 * @brief A callback that returns an object that will handle the relayed data.
 * TcpRelayDataProcessorCb will only be called for relay data from the "from"
 * endpoint to the "to" endpoint.
 *
 * @param from data sender endpoint to the socks5 proxy.
 * @param to data receiver endpoint from the socks5 proxy.
 * @return TcpRelayDataProcessorCb
 */
using TcpRelayDataProcessorCreatorCb = std::function<TcpRelayDataProcessorCb(
    const tcp::endpoint& from, const tcp::endpoint& to)>;

/**
 * @brief A callback that processes UDP data relayed through the socks5
 * proxy server.
 *
 * @param data pointer to relayed data.
 * @param size data size.
 * @param server target server endpoint to which the data will be sent.
 * @param send callback that will asynchronously send data to the network.
 */
using UdpRelayDataFromClientProcessorCb = std::function<void(
    const char* data, size_t size, const udp::endpoint& server,
    const RelayDataSender& send)>;

/**
 * @brief A callback that returns an object that will handle the data being
 * relayed from the client to the server. UdpRelayDataFromClientProcessorCb will
 * only be called for relay data from the "client" endpoint.
 *
 * @param expected_client_ep the client endpoint from which datagrams are
 * expected. The client sends this address in the socsk5 request when
 * establishing a
 * connection(https://datatracker.ietf.org/doc/html/rfc1928#section-6). If the
 * client sends a zero address, the ip address of the tcp socket for the
 * endpoint will be taken, and the port will be set to 0, meaning the proxy will
 * process requests from any port.
 * @return UdpRelayDataFromClientProcessorCb
 */
using UdpRelayDataFromClientProcessorCreatorCb =
    std::function<UdpRelayDataFromClientProcessorCb(
        const udp::endpoint& expected_client_ep)>;

/**
 * @brief A callback that processes UDP data relayed through the socks5 proxy
 * server.
 *
 * @param data pointer to relayed data.
 * @param size data size.
 * @param send callback that will asynchronously send data to the network.
 */
using UdpRelayDataProcessorCb = std::function<void(
    const char* data, size_t size, const RelayDataSender& send)>;

/**
 * @brief A callback that returns an object that will handle the data being
 * relayed from the server to the client. UdpRelayDataProcessorCb will only be
 * called for relay data from the "server" endpoint to the "client" endpoint.
 *
 * @param client client endpoint.
 * @param server server endpoint.
 * @return UdpRelayDataProcessorCb
 */
using UdpRelayDataProcessorCreatorCb = std::function<UdpRelayDataProcessorCb(
    const udp::endpoint& client, const udp::endpoint& server)>;

/**
 * @brief A callbacks that create objects that handle all TCP data relayed
 * through the socks5 proxy.
 */
struct SOCKS5_API TcpRelayDataProcessor final {
  // A callback that returns an object that will handle the data being relayed
  // from the client to the server.
  TcpRelayDataProcessorCreatorCb client_to_server;
  // A callback that returns an object that will handle the data being relayed
  // from the server to the client.
  TcpRelayDataProcessorCreatorCb server_to_client;
};

/**
 * @brief A callbacks that create objects that handle all UDP data relayed
 * through the socks5 proxy.
 */
struct SOCKS5_API UdpRelayDataProcessor final {
  UdpRelayDataFromClientProcessorCreatorCb client_to_server;
  UdpRelayDataProcessorCreatorCb server_to_client;
};

using TcpRelayDataProcessorPtr = std::shared_ptr<TcpRelayDataProcessor>;
using UdpRelayDataProcessorPtr = std::shared_ptr<UdpRelayDataProcessor>;

}  // namespace socks5::server