#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/client/defs.hpp>
#include <client/udp_associate_handshake.hpp>
#include <socks5/common/address.hpp>
#include <socks5/common/datagram_buffer.hpp>

namespace socks5::client {

VoidAwait RunConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                     common::Address target_server_ep,
                     auth::client::AuthOptions auth_options, size_t timeout,
                     ConnectHandler handler);
VoidAwait RunBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  tcp::endpoint inbound_connect_ep,
                  auth::client::AuthOptions auth_options, size_t timeout,
                  FirstBindReplyHandler first_reply_handler,
                  SecondBindReplyHandler second_reply_handler);

VoidAwait RunConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                     common::Address target_server_ep,
                     auth::client::AuthOptions auth_options,
                     ConnectHandler handler);
VoidAwait RunBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  tcp::endpoint inbound_connect_ep,
                  auth::client::AuthOptions auth_options,
                  FirstBindReplyHandler first_reply_handler,
                  SecondBindReplyHandler second_reply_handler);

ErrorAwait RunConnect(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
                      const common::Address& target_server_ep,
                      const auth::client::AuthOptions& auth_options,
                      size_t timeout) noexcept;
UdpAssociateResultOrErrorAwait RunUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept;
TcpEndpointOrErrorAwait RunFirstBindStep(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept;
TcpEndpointOrErrorAwait RunSecondBindStep(tcp::socket& socket,
                                          size_t timeout) noexcept;

BytesCountOrErrorAwait RunSendTo(udp::socket& socket,
                                 const udp::endpoint& proxy_server_ep,
                                 const common::Address& target_server_addr,
                                 const char* data, size_t size,
                                 size_t timeout) noexcept;
BytesCountOrErrorAwait RunReceiveFrom(udp::socket& socket,
                                      udp::endpoint& proxy_sender_ep,
                                      common::Address& sender_addr,
                                      common::DatagramBuffer& buf,
                                      size_t timeout) noexcept;

ErrorAwait RunConnect(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
                      const common::Address& target_server_ep,
                      const auth::client::AuthOptions& auth_options) noexcept;
UdpAssociateResultOrErrorAwait RunUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options) noexcept;
TcpEndpointOrErrorAwait RunFirstBindStep(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options) noexcept;
TcpEndpointOrErrorAwait RunSecondBindStep(tcp::socket& socket) noexcept;

BytesCountOrErrorAwait RunSendTo(udp::socket& socket,
                                 const udp::endpoint& proxy_server_ep,
                                 const common::Address& target_server_addr,
                                 const char* data, size_t size) noexcept;
BytesCountOrErrorAwait RunReceiveFrom(udp::socket& socket,
                                      udp::endpoint& proxy_sender_ep,
                                      common::Address& sender_addr,
                                      common::DatagramBuffer& buf) noexcept;
}  // namespace socks5::client