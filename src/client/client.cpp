#include <socks5/client/client.hpp>
#include <client/invokers.hpp>

namespace socks5::client {

void AsyncConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  common::Address target_server_addr,
                  auth::client::AuthOptions auth_options, size_t timeout,
                  ConnectHandler handler) {
  asio::co_spawn(
      asio::make_strand(socket.get_executor()),
      RunConnect(socket, std::move(proxy_server_ep),
                 std::move(target_server_addr), std::move(auth_options),
                 timeout, std::move(handler)),
      asio::detached);
}

void AsyncBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
               tcp::endpoint inbound_connect_ep,
               auth::client::AuthOptions auth_options, size_t timeout,
               FirstBindReplyHandler first_reply_handler,
               SecondBindReplyHandler second_reply_handler) {
  asio::co_spawn(
      asio::make_strand(socket.get_executor()),
      RunBind(socket, std::move(proxy_server_ep), std::move(inbound_connect_ep),
              std::move(auth_options), timeout, std::move(first_reply_handler),
              std::move(second_reply_handler)),
      asio::detached);
}

void AsyncConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  common::Address target_server_addr,
                  auth::client::AuthOptions auth_options,
                  ConnectHandler handler) {
  asio::co_spawn(asio::make_strand(socket.get_executor()),
                 RunConnect(socket, std::move(proxy_server_ep),
                            std::move(target_server_addr),
                            std::move(auth_options), std::move(handler)),
                 asio::detached);
}

void AsyncBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
               tcp::endpoint inbound_connect_ep,
               auth::client::AuthOptions auth_options,
               FirstBindReplyHandler first_reply_handler,
               SecondBindReplyHandler second_reply_handler) {
  asio::co_spawn(
      asio::make_strand(socket.get_executor()),
      RunBind(socket, std::move(proxy_server_ep), std::move(inbound_connect_ep),
              std::move(auth_options), std::move(first_reply_handler),
              std::move(second_reply_handler)),
      asio::detached);
}

ErrorAwait AsyncConnect(tcp::socket& socket,
                        const tcp::endpoint& proxy_server_ep,
                        const common::Address& target_server_addr,
                        const auth::client::AuthOptions& auth_options,
                        size_t timeout) noexcept {
  co_return co_await RunConnect(socket, proxy_server_ep, target_server_addr,
                                auth_options, timeout);
}

UdpAssociateResultOrErrorAwait AsyncUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept {
  co_return co_await RunUdpAssociate(socket, proxy_server_ep, auth_options,
                                     timeout);
}

BytesCountOrErrorAwait AsyncSendTo(udp::socket& socket,
                                   const udp::endpoint& proxy_server_ep,
                                   const common::Address& target_server_addr,
                                   const char* data, size_t size,
                                   size_t timeout) noexcept {
  co_return co_await RunSendTo(socket, proxy_server_ep, target_server_addr,
                               data, size, timeout);
}

BytesCountOrErrorAwait AsyncReceiveFrom(udp::socket& socket,
                                        udp::endpoint& proxy_sender_ep,
                                        common::Address& sender_addr,
                                        common::DatagramBuffer& buf,
                                        size_t timeout) noexcept {
  co_return co_await RunReceiveFrom(socket, proxy_sender_ep, sender_addr, buf,
                                    timeout);
}

TcpEndpointOrErrorAwait FirstBindStep(tcp::socket& socket,
                                      tcp::endpoint proxy_server_ep,
                                      tcp::endpoint inbound_connect_ep,
                                      auth::client::AuthOptions auth_options,
                                      size_t timeout) noexcept {
  co_return co_await RunFirstBindStep(
      socket, proxy_server_ep, inbound_connect_ep, auth_options, timeout);
}

TcpEndpointOrErrorAwait SecondBindStep(tcp::socket& socket,
                                       size_t timeout) noexcept {
  co_return co_await RunSecondBindStep(socket, timeout);
}

ErrorAwait AsyncConnect(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const common::Address& target_server_addr,
    const auth::client::AuthOptions& auth_options) noexcept {
  co_return co_await RunConnect(socket, proxy_server_ep, target_server_addr,
                                auth_options);
}

UdpAssociateResultOrErrorAwait AsyncUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options) noexcept {
  co_return co_await RunUdpAssociate(socket, proxy_server_ep, auth_options);
}

BytesCountOrErrorAwait AsyncSendTo(udp::socket& socket,
                                   const udp::endpoint& proxy_server_ep,
                                   const common::Address& target_server_addr,
                                   const char* data, size_t size) noexcept {
  co_return co_await RunSendTo(socket, proxy_server_ep, target_server_addr,
                               data, size);
}

BytesCountOrErrorAwait AsyncReceiveFrom(udp::socket& socket,
                                        udp::endpoint& proxy_sender_ep,
                                        common::Address& sender_addr,
                                        common::DatagramBuffer& buf) noexcept {
  co_return co_await RunReceiveFrom(socket, proxy_sender_ep, sender_addr, buf);
}

TcpEndpointOrErrorAwait FirstBindStep(
    tcp::socket& socket, tcp::endpoint proxy_server_ep,
    tcp::endpoint inbound_connect_ep,
    auth::client::AuthOptions auth_options) noexcept {
  co_return co_await RunFirstBindStep(socket, proxy_server_ep,
                                      inbound_connect_ep, auth_options);
}

TcpEndpointOrErrorAwait SecondBindStep(tcp::socket& socket) noexcept {
  co_return co_await RunSecondBindStep(socket);
}

}  // namespace socks5::client