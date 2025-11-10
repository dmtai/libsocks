#pragma once

#include <socks5/common/asio.hpp>
#include <functional>
#include <socks5/common/api_macro.hpp>
#include <socks5/utils/status.hpp>

namespace socks5::client {

/**
 * @brief The result of establishing a connection with a socks5 proxy for
 * relaying data via udp. Contains a udp socket, with which the socks5 proxy is
 * connected and which should be used to relay data to target servers via the
 * socks5 proxy. It also contains an endpoint with an address on the socks5
 * proxy, to which data should be sent for relaying.
 */
struct SOCKS5_API UdpAssociateResult final {
  // Socket for receiving/sending data to the proxy.
  udp::socket udp_socket;
  // Proxy endpoint for sending data to it.
  udp::endpoint proxy_ep;
};

using UdpAssociateResultOpt = std::optional<UdpAssociateResult>;
using UdpAssociateResultOrError = utils::ErrorOr<UdpAssociateResultOpt>;

using ConnectHandler =
    std::function<void(const boost::system::error_code& err)>;
using UdpAssociateHandler = std::function<void(
    const boost::system::error_code& err, UdpAssociateResultOpt uar)>;

/**
 * @brief Callback with error_code and endpoint with the address where the
 * incoming connection is expected on the socks5 proxy.
 */
using FirstBindReplyHandler = std::function<void(
    const boost::system::error_code& err, const tcp::endpoint& bind_ep)>;

/**
 * @brief Callback with error_code and endpoint with the address of the
 * connection accepted by the socks5 proxy.
 */
using SecondBindReplyHandler = std::function<void(
    const boost::system::error_code& err, const tcp::endpoint& accepted_ep)>;

using BindReplyOrError = utils::ErrorOr<tcp::endpoint>;

#ifdef __cpp_impl_coroutine
using UdpAssociateResultOrErrorAwait =
    asio::awaitable<UdpAssociateResultOrError>;
#endif

}  // namespace socks5::client