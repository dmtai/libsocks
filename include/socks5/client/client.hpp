#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/client/defs.hpp>
#include <socks5/common/api_macro.hpp>
#include <socks5/common/datagram_buffer.hpp>
#include <socks5/common/address.hpp>

namespace socks5::client {

/**
 * @brief Start an asynchronous TCP relay connection to the target server via a
 * socks5 proxy. The CONNECT command is sent to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made.
 * @param proxy_server_ep socks5 proxy server address.
 * @param target_server_addr target server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param timeout connection timeout in milliseconds.
 * @param handler the handler to be called when the connection operation
 * completes.
 * @throws std::exception
 */
SOCKS5_API void AsyncConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                             common::Address target_server_addr,
                             auth::client::AuthOptions auth_options,
                             size_t timeout, ConnectHandler handler);

/**
 * @brief Start an asynchronous connection to the target server via a
 * socks5 proxy to accepting incoming connection. The BIND command is sent
 * to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * @param proxy_server_ep socks5 proxy server address.
 * @param inbound_connect_ep the address from which the incoming connection to
 * the proxy server will be established.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param timeout connection timeout in milliseconds.
 * @param first_reply_handler the handler that will be called after creating an
 * acceptor on the proxy server that is waiting for an incoming connection. The
 * handler will be passed an endpoint with the address where the incoming
 * connection is expected on the socks5 proxy.
 * @param second_reply_handler the handler that will be called after the proxy
 * server receives an incoming connection. The handler will receive an endpoint
 * with the address of the connection accepted by the socks5 proxy server. After
 * calling this handler, you can retransmit data to the accepted incoming
 * connection via the socket passed to this function.
 * @throws std::exception
 */
SOCKS5_API void AsyncBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                          tcp::endpoint inbound_connect_ep,
                          auth::client::AuthOptions auth_options,
                          size_t timeout,
                          FirstBindReplyHandler first_reply_handler,
                          SecondBindReplyHandler second_reply_handler);

/**
 * @brief Start an asynchronous TCP relay connection to the target server via a
 * socks5 proxy. The CONNECT command is sent to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made.
 * @param proxy_server_ep socks5 proxy server address.
 * @param target_server_addr target server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param handler the handler to be called when the connection operation
 * completes.
 * @throws std::exception
 */
SOCKS5_API void AsyncConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                             common::Address target_server_addr,
                             auth::client::AuthOptions auth_options,
                             ConnectHandler handler);

/**
 * @brief Start an asynchronous connection to the target server via a
 * socks5 proxy to accepting incoming connection. The BIND command is sent
 * to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * @param proxy_server_ep socks5 proxy server address.
 * @param inbound_connect_ep the address from which the incoming connection to
 * the proxy server will be established.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param first_reply_handler the handler that will be called after creating an
 * acceptor on the proxy server that is waiting for an incoming connection. The
 * handler will be passed an endpoint with the address where the incoming
 * connection is expected on the socks5 proxy.
 * @param second_reply_handler the handler that will be called after the proxy
 * server receives an incoming connection. The handler will receive an endpoint
 * with the address of the connection accepted by the socks5 proxy server. After
 * calling this handler, you can retransmit data to the accepted incoming
 * connection via the socket passed to this function.
 * @throws std::exception
 */
SOCKS5_API void AsyncBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                          tcp::endpoint inbound_connect_ep,
                          auth::client::AuthOptions auth_options,
                          FirstBindReplyHandler first_reply_handler,
                          SecondBindReplyHandler second_reply_handler);

#ifdef __cpp_impl_coroutine

/**
 * @brief Start an asynchronous TCP relay connection to the target server via a
 * socks5 proxy. The CONNECT command is sent to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made.
 * @param proxy_server_ep socks5 proxy server address.
 * @param target_server_addr target server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param timeout connection timeout in milliseconds.
 * @return ErrorAwait asio::awaitable with boost::system::error_code.
 */
SOCKS5_API ErrorAwait AsyncConnect(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const common::Address& target_server_addr,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept;

/**
 * @brief Start an asynchronous UDP relay connection to the target servers via a
 * socks5 proxy. The UDP ASSOCIATE command is sent to the socks5 proxy.
 *
 * @param socket the TCP socket on which the asynchronous connection will
 * be made. The TCP socket must live for the entire duration of the UDP relay.
 * When it is closed, the UDP relay will be terminated. It will also be used for
 * authentication.
 * @param proxy_server_ep socks5 proxy server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param timeout connection timeout in milliseconds.
 * @return UdpAssociateResultOrErrorAwait asio::awaitable with
 * UdpAssociateResult that contains data for UDP relay or
 * boost::system::error_code if an error occurred.
 */
SOCKS5_API UdpAssociateResultOrErrorAwait AsyncUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept;

/**
 * @brief Asynchronously sends data via UDP to the target server via a socks5
 * proxy. Before calling this function, you must establish a connection
 * to the socks5 proxy using AsyncUdpAssociate.
 *
 * @param socket UdpAssociateResult.udp_socket which was returned by
 * AsyncUdpAssociate.
 * @param proxy_server_ep UdpAssociateResult.proxy_ep which was returned by
 * AsyncUdpAssociate.
 * @param target_server_addr the address of the target server to which the data
 * will be sent via socks5 proxy.
 * @param data to send.
 * @param size of data sent.
 * @param timeout in milliseconds for send operation.
 * @return BytesCountOrErrorAwait asio::awaitable with the count of bytes sent,
 * or boost::system::error_code if an error occurred.
 */
SOCKS5_API BytesCountOrErrorAwait
AsyncSendTo(udp::socket& socket, const udp::endpoint& proxy_server_ep,
            const common::Address& target_server_addr, const char* data,
            size_t size, size_t timeout) noexcept;

/**
 * @brief Asynchronously receives data via UDP from the target servers via a
 * socks5 proxy. Before calling this function, you must establish a connection
 * to the socks5 proxy using AsyncUdpAssociate.
 *
 * @param socket UdpAssociateResult.udp_socket which was returned by
 * AsyncUdpAssociate.
 * @param proxy_sender_ep output parameter that will contain the endpoint of the
 * socks5 proxy that sent the datagram.
 * @param sender_addr output parameter that will contain the address of the
 * datagram sender to the socks5 proxy.
 * @param buf with read data.
 * @param timeout in milliseconds for receive operation.
 * @return BytesCountOrErrorAwait asio::awaitable with the count of bytes
 * received, or boost::system::error_code if an error occurred.
 */
SOCKS5_API BytesCountOrErrorAwait
AsyncReceiveFrom(udp::socket& socket, udp::endpoint& proxy_sender_ep,
                 common::Address& sender_addr, common::DatagramBuffer& buf,
                 size_t timeout) noexcept;

/**
 * @brief Start an asynchronous connection to the target server via a
 * socks5 proxy to accepting incoming connection. The BIND command is sent
 * to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * @param proxy_server_ep socks5 proxy server address.
 * @param inbound_connect_ep the address from which the incoming connection to
 * the proxy server will be established.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @param timeout in milliseconds for operation.
 * @return TcpEndpointOrErrorAwait asio::awaitable with tcp::endpoint with the
 * address of the acceptor on the socks5 proxy to which the target server
 * should connect, or boost::system::error_code if an error occurred.
 */
SOCKS5_API TcpEndpointOrErrorAwait
FirstBindStep(tcp::socket& socket, tcp::endpoint proxy_server_ep,
              tcp::endpoint inbound_connect_ep,
              auth::client::AuthOptions auth_options, size_t timeout) noexcept;

/**
 * @brief Waits for the socks5 proxy to receive an incoming connection
 * from the target server. After this function is successfully completed, you
 * can start relaying data with the incoming connection received from the target
 * server through the socks5 proxy. Called after FirstBindStep.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * The same as in FirstBindStep.
 * @param t.
 * @return TcpEndpointOrErrorAwait asio::awaitable with tcp::endpoint with the
 * address of the connection accepted by the socks5 proxy server, or
 * boost::system::error_code if an error occurred.
 */
SOCKS5_API TcpEndpointOrErrorAwait SecondBindStep(tcp::socket& socket,
                                                  size_t timeout) noexcept;

/**
 * @brief Start an asynchronous TCP relay connection to the target server via a
 * socks5 proxy. The CONNECT command is sent to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made.
 * @param proxy_server_ep socks5 proxy server address.
 * @param target_server_addr target server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @return ErrorAwait asio::awaitable with boost::system::error_code.
 */
SOCKS5_API ErrorAwait
AsyncConnect(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
             const common::Address& target_server_addr,
             const auth::client::AuthOptions& auth_options) noexcept;

/**
 * @brief Start an asynchronous UDP relay connection to the target servers via a
 * socks5 proxy. The UDP ASSOCIATE command is sent to the socks5 proxy.
 *
 * @param socket the TCP socket on which the asynchronous connection will
 * be made. The TCP socket must live for the entire duration of the UDP relay.
 * When it is closed, the UDP relay will be terminated. It will also be used for
 * authentication.
 * @param proxy_server_ep socks5 proxy server address.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @return UdpAssociateResultOrErrorAwait asio::awaitable with
 * UdpAssociateResult that contains data for UDP relay or
 * boost::system::error_code if an error occurred.
 */
SOCKS5_API UdpAssociateResultOrErrorAwait
AsyncUdpAssociate(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
                  const auth::client::AuthOptions& auth_options) noexcept;

/**
 * @brief Asynchronously sends data via UDP to the target server via a socks5
 * proxy. Before calling this function, you must establish a connection
 * to the socks5 proxy using AsyncUdpAssociate.
 *
 * @param socket UdpAssociateResult.udp_socket which was returned by
 * AsyncUdpAssociate.
 * @param proxy_server_ep UdpAssociateResult.proxy_ep which was returned by
 * AsyncUdpAssociate.
 * @param target_server_addr the address of the target server to which the data
 * will be sent via socks5 proxy.
 * @param data to send.
 * @param size of data sent.
 * @return BytesCountOrErrorAwait asio::awaitable with the count of bytes sent,
 * or boost::system::error_code if an error occurred.
 */
SOCKS5_API BytesCountOrErrorAwait
AsyncSendTo(udp::socket& socket, const udp::endpoint& proxy_server_ep,
            const common::Address& target_server_addr, const char* data,
            size_t size) noexcept;

/**
 * @brief Asynchronously receives data via UDP from the target servers via a
 * socks5 proxy. Before calling this function, you must establish a connection
 * to the socks5 proxy using AsyncUdpAssociate.
 *
 * @param socket UdpAssociateResult.udp_socket which was returned by
 * AsyncUdpAssociate.
 * @param proxy_sender_ep UdpAssociateResult.proxy_ep which was returned by
 * AsyncUdpAssociate.
 * @param sender_addr output parameter, which will contain the address of the
 * datagram sender to the socks5 proxy.
 * @param buf with read data.
 * @return BytesCountOrErrorAwait asio::awaitable with the count of bytes
 * received, or boost::system::error_code if an error occurred.
 */
SOCKS5_API BytesCountOrErrorAwait AsyncReceiveFrom(
    udp::socket& socket, udp::endpoint& proxy_sender_ep,
    common::Address& sender_addr, common::DatagramBuffer& buf) noexcept;

/**
 * @brief Start an asynchronous connection to the target server via a
 * socks5 proxy to accepting incoming connection. The BIND command is sent
 * to the socks5 proxy.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * @param proxy_server_ep socks5 proxy server address.
 * @param inbound_connect_ep the address from which the incoming connection to
 * the proxy server will be established.
 * @param auth_options authentication parameters for socks5 proxy server.
 * @return TcpEndpointOrErrorAwait asio::awaitable with tcp::endpoint with the
 * address of the acceptor on the socks5 proxy to which the target server
 * should connect, or boost::system::error_code if an error occurred.
 */
SOCKS5_API TcpEndpointOrErrorAwait
FirstBindStep(tcp::socket& socket, tcp::endpoint proxy_server_ep,
              tcp::endpoint inbound_connect_ep,
              auth::client::AuthOptions auth_options) noexcept;

/**
 * @brief Waits for the socks5 proxy to receive an incoming connection
 * from the target server. After this function is successfully completed, you
 * can start relaying data with the incoming connection received from the target
 * server through the socks5 proxy. Called after FirstBindStep.
 *
 * @param socket the socket on which the asynchronous connection will
 * be made. This socket will be used to relay data with the incoming connection.
 * The same as in FirstBindStep.
 * @return TcpEndpointOrErrorAwait asio::awaitable with tcp::endpoint with the
 * address of the connection accepted by the socks5 proxy server, or
 * boost::system::error_code if an error occurred.
 */
SOCKS5_API TcpEndpointOrErrorAwait SecondBindStep(tcp::socket& socket) noexcept;

#endif

}  // namespace socks5::client