#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/common/address.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/server/config.hpp>

namespace socks5::server {

#ifdef __cpp_impl_coroutine

/**
 * @brief A callback that implements the logic for relaying TCP data.
 *
 * @param io_context internal socks5 proxy server boost::asio io_context.
 * @param client socket to client.
 * @param server socket to target server.
 * @param config socks5 proxy server config.
 * @param metrics object with socks5 proxy server metrics. If you want the
 * metrics to remain correct, you will have to support them in your relay logic
 * implementation. This is not necessary, but the metrics will not work then.
 * @return asio::awaitable<void>
 */
using CoroTcpRelayHandlerCb = VoidAwait (*)(asio::io_context& io_context,
                                            socks5::tcp::socket client,
                                            socks5::tcp::socket server,
                                            const Config& config,
                                            common::Metrics& metrics);

/**
 * @brief A callback that implements the logic for relaying UDP data.
 *
 * @param io_context internal socks5 proxy server boost::asio io_context.
 * @param client client tcp socket.
 * @param proxy socket on the socks5 proxy server to which the client will send
 * datagrams.
 * @param address client address for udp relay.
 * @param config socks5 proxy server config.
 * @param metrics object with socks5 proxy server metrics. If you want the
 * metrics to remain correct, you will have to support them in your relay logic
 * implementation. This is not necessary, but the metrics will not work then.
 * @return asio::awaitable<void>
 */
using CoroUdpRelayHandlerCb = VoidAwait (*)(
    asio::io_context& io_context, tcp::socket client, udp::socket proxy,
    common::Address address, const Config& config, common::Metrics& metrics);
#endif

/**
 * @brief A callback that implements the logic for relaying TCP data.
 *
 * @param io_context internal socks5 proxy server boost::asio io_context.
 * @param client socket to client.
 * @param server socket to target server.
 * @param config socks5 proxy server config.
 * @param metrics object with socks5 proxy server metrics. If you want the
 * metrics to remain correct, you will have to support them in your relay logic
 * implementation. This is not necessary, but the metrics will not work then.
 */
using TcpRelayHandlerCb = void (*)(asio::io_context& io_context,
                                   socks5::tcp::socket client,
                                   socks5::tcp::socket server,
                                   const Config& config,
                                   common::Metrics& metrics);

/**
 * @brief A callback that implements the logic for relaying UDP data.
 *
 * @param io_context internal socks5 proxy server boost::asio io_context.
 * @param client client tcp socket.
 * @param proxy socket on the socks5 proxy server to which the client will send
 * datagrams.
 * @param address client address for udp relay.
 * @param config socks5 proxy server config.
 * @param metrics object with socks5 proxy server metrics. If you want the
 * metrics to remain correct, you will have to support them in your relay logic
 * implementation. This is not necessary, but the metrics will not work then.
 */
using UdpRelayHandlerCb = void (*)(asio::io_context& io_context,
                                   tcp::socket client, udp::socket proxy,
                                   common::Address address,
                                   const Config& config,
                                   common::Metrics& metrics);

}  // namespace socks5::server