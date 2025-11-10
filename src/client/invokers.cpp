#include <client/invokers.hpp>
#include <utils/logger.hpp>
#include <net/utils.hpp>
#include <client/connect_handshake.hpp>
#include <client/bind_handshake.hpp>
#include <socks5/error/error.hpp>
#include <client/udp_associate_handshake.hpp>
#include <utils/timeout.hpp>
#include <common/proto_builders.hpp>
#include <serializers/serializers.hpp>
#include <parsers/parsers.hpp>
#include <net/io.hpp>
#include <socks5/utils/buffer.hpp>
#include <common/socks5_datagram_validator.hpp>
#include <socks5/common/address.hpp>
#include <proto/proto.hpp>
#include <common/socks5_datagram_io.hpp>

namespace socks5::client {

namespace {

ErrorAwait RunConnectImpl(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const common::Address& target_server_addr,
    const auth::client::AuthOptions& auth_options) noexcept {
  if (target_server_addr.IsEmpty()) {
    co_return error::Error::kInvalidAddress;
  }
  const auto [err] =
      co_await socket.async_connect(proxy_server_ep, use_nothrow_awaitable);
  if (err) {
    co_return err;
  }
  ConnectHandshake handshake{socket, target_server_addr, auth_options};
  if (const auto err = co_await handshake.Run()) {
    co_return err;
  }
  co_return error::Error::kSucceeded;
}

ErrorAwait RunConnectImpl(tcp::socket& socket,
                          const tcp::endpoint& proxy_server_ep,
                          const common::Address& target_server_addr,
                          const auth::client::AuthOptions& auth_options,
                          size_t timeout) noexcept {
  try {
    const auto res =
        co_await (RunConnectImpl(socket, proxy_server_ep, target_server_addr,
                                 auth_options) ||
                  utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return error::Error::kTimeoutExpired;
    }
    co_return std::move(std::get<0>(res));
  } catch (...) {
    co_return error::Error::kCancellationFailure;
  }
}

UdpAssociateResultOrErrorAwait RunUdpAssociateImpl(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options) noexcept {
  const auto [err] =
      co_await socket.async_connect(proxy_server_ep, use_nothrow_awaitable);
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  UdpAssociateHandshake handshake{socket, auth_options};
  co_return co_await handshake.Run();
}

UdpAssociateResultOrErrorAwait RunUdpAssociateImpl(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept {
  try {
    auto res =
        co_await (RunUdpAssociateImpl(socket, proxy_server_ep, auth_options) ||
                  utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return std::make_pair(error::Error::kTimeoutExpired, std::nullopt);
    }
    co_return std::move(std::get<0>(res));
  } catch (...) {
    co_return std::make_pair(error::Error::kCancellationFailure, std::nullopt);
  }
}

BytesCountOrErrorAwait RunSendToImpl(udp::socket& socket,
                                     const udp::endpoint& proxy_server_ep,
                                     const common::Address& target_server_addr,
                                     const char* data, size_t size,
                                     size_t timeout) noexcept {
  try {
    auto res = co_await (common::SendTo(socket, proxy_server_ep,
                                        target_server_addr, data, size) ||
                         utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return std::make_pair(error::Error::kTimeoutExpired, 0);
    }
    co_return std::move(std::get<0>(res));
  } catch (const std::exception&) {
    co_return std::make_pair(error::Error::kCancellationFailure, 0);
  }
}

BytesCountOrErrorAwait RunSendToImpl(udp::socket& socket,
                                     const udp::endpoint& proxy_server_ep,
                                     const common::Address& target_server_addr,
                                     const char* data, size_t size) noexcept {
  co_return co_await common::SendTo(socket, proxy_server_ep, target_server_addr,
                                    data, size);
}

BytesCountOrErrorAwait RunReceiveFromImpl(udp::socket& socket,
                                          udp::endpoint& proxy_sender_ep,
                                          common::Address& sender_addr,
                                          common::DatagramBuffer& buf,
                                          size_t timeout) noexcept {
  try {
    auto res = co_await (
        common::ReceiveFrom(socket, proxy_sender_ep, sender_addr, buf) ||
        utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return std::make_pair(error::Error::kTimeoutExpired, 0);
    }
    co_return std::move(std::get<0>(res));
  } catch (...) {
    co_return std::make_pair(error::Error::kCancellationFailure, 0);
  }
}

BytesCountOrErrorAwait RunReceiveFromImpl(
    udp::socket& socket, udp::endpoint& proxy_sender_ep,
    common::Address& sender_addr, common::DatagramBuffer& buf) noexcept {
  co_return co_await common::ReceiveFrom(socket, proxy_sender_ep, sender_addr,
                                         buf);
}

TcpEndpointOrErrorAwait RunFirstBindStepImpl(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options) noexcept {
  const auto [err] =
      co_await socket.async_connect(proxy_server_ep, use_nothrow_awaitable);
  if (err) {
    co_return std::make_pair(std::move(err), tcp::endpoint{});
  }
  BindHandshake handshake{socket, inbound_connect_ep, auth_options};
  if (const auto err = co_await handshake.Auth()) {
    co_return std::make_pair(std::move(err), tcp::endpoint{});
  }
  if (const auto err = co_await handshake.SendRequest()) {
    co_return std::make_pair(std::move(err), tcp::endpoint{});
  }
  auto [reply_err, bind_ep] = co_await handshake.ProcessFirstReply();
  if (reply_err) {
    co_return std::make_pair(std::move(reply_err), tcp::endpoint{});
  }
  co_return std::make_pair(error::Error::kSucceeded, std::move(bind_ep));
}

TcpEndpointOrErrorAwait RunSecondBindStepImpl(tcp::socket& socket) noexcept {
  BindHandshake handshake{socket, tcp::endpoint{}, auth::client::AuthOptions{}};
  const auto [reply_err, accepted_ep] = co_await handshake.ProcessSecondReply();
  if (reply_err) {
    co_return std::make_pair(std::move(reply_err), tcp::endpoint{});
  }
  co_return std::make_pair(error::Error::kSucceeded, std::move(accepted_ep));
}

}  // namespace

VoidAwait RunConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                     common::Address target_server_ep,
                     auth::client::AuthOptions auth_options, size_t timeout,
                     ConnectHandler handler) {
  const auto res = co_await RunConnectImpl(
      socket, proxy_server_ep, target_server_ep, auth_options, timeout);
  handler(res);
}

VoidAwait RunBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  tcp::endpoint inbound_connect_ep,
                  auth::client::AuthOptions auth_options, size_t timeout,
                  FirstBindReplyHandler first_reply_handler,
                  SecondBindReplyHandler second_reply_handler) {
  const auto [first_err, first_ep] = co_await RunFirstBindStep(
      socket, proxy_server_ep, inbound_connect_ep, auth_options, timeout / 2);
  first_reply_handler(first_err, first_ep ? *first_ep : tcp::endpoint{});
  if (first_err) {
    co_return;
  }
  const auto [second_err, second_ep] =
      co_await RunSecondBindStep(socket, timeout / 2);
  second_reply_handler(second_err, second_ep ? *second_ep : tcp::endpoint{});
}

VoidAwait RunConnect(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                     common::Address target_server_ep,
                     auth::client::AuthOptions auth_options,
                     ConnectHandler handler) {
  const auto res = co_await RunConnectImpl(socket, proxy_server_ep,
                                           target_server_ep, auth_options);
  handler(res);
}

VoidAwait RunBind(tcp::socket& socket, tcp::endpoint proxy_server_ep,
                  tcp::endpoint inbound_connect_ep,
                  auth::client::AuthOptions auth_options,
                  FirstBindReplyHandler first_reply_handler,
                  SecondBindReplyHandler second_reply_handler) {
  const auto [first_err, first_ep] = co_await RunFirstBindStep(
      socket, proxy_server_ep, inbound_connect_ep, auth_options);
  first_reply_handler(first_err, first_ep ? *first_ep : tcp::endpoint{});
  if (first_err) {
    co_return;
  }
  const auto [second_err, second_ep] = co_await RunSecondBindStep(socket);
  second_reply_handler(second_err, second_ep ? *second_ep : tcp::endpoint{});
}

ErrorAwait RunConnect(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
                      const common::Address& target_server_addr,
                      const auth::client::AuthOptions& auth_options,
                      size_t timeout) noexcept {
  co_return co_await RunConnectImpl(socket, proxy_server_ep, target_server_addr,
                                    auth_options, timeout);
}

UdpAssociateResultOrErrorAwait RunUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept {
  co_return co_await RunUdpAssociateImpl(socket, proxy_server_ep, auth_options,
                                         timeout);
}

TcpEndpointOrErrorAwait RunFirstBindStep(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options, size_t timeout) noexcept {
  try {
    auto res =
        co_await (RunFirstBindStepImpl(socket, proxy_server_ep,
                                       inbound_connect_ep, auth_options) ||
                  utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return std::make_pair(error::Error::kTimeoutExpired, std::nullopt);
    }
    co_return std::move(std::get<0>(res));
  } catch (...) {
    co_return std::make_pair(error::Error::kCancellationFailure, std::nullopt);
  }
}

TcpEndpointOrErrorAwait RunSecondBindStep(tcp::socket& socket,
                                          size_t timeout) noexcept {
  try {
    auto res =
        co_await (RunSecondBindStepImpl(socket) || utils::Timeout(timeout));
    if (res.index() == 1) {
      co_return std::make_pair(error::Error::kTimeoutExpired, std::nullopt);
    }
    co_return std::move(std::get<0>(res));
  } catch (...) {
    co_return std::make_pair(error::Error::kCancellationFailure, std::nullopt);
  }
}

BytesCountOrErrorAwait RunSendTo(udp::socket& socket,
                                 const udp::endpoint& proxy_server_ep,
                                 const common::Address& target_server_addr,
                                 const char* data, size_t size,
                                 size_t timeout) noexcept {
  co_return co_await RunSendToImpl(socket, proxy_server_ep, target_server_addr,
                                   data, size, timeout);
}

BytesCountOrErrorAwait RunReceiveFrom(udp::socket& socket,
                                      udp::endpoint& proxy_sender_ep,
                                      common::Address& sender_addr,
                                      common::DatagramBuffer& buf,
                                      size_t timeout) noexcept {
  co_return co_await RunReceiveFromImpl(socket, proxy_sender_ep, sender_addr,
                                        buf, timeout);
}

ErrorAwait RunConnect(tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
                      const common::Address& target_server_addr,
                      const auth::client::AuthOptions& auth_options) noexcept {
  co_return co_await RunConnectImpl(socket, proxy_server_ep, target_server_addr,
                                    auth_options);
}

UdpAssociateResultOrErrorAwait RunUdpAssociate(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const auth::client::AuthOptions& auth_options) noexcept {
  co_return co_await RunUdpAssociateImpl(socket, proxy_server_ep, auth_options);
}

TcpEndpointOrErrorAwait RunFirstBindStep(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& inbound_connect_ep,
    const auth::client::AuthOptions& auth_options) noexcept {
  co_return co_await RunFirstBindStepImpl(socket, proxy_server_ep,
                                          inbound_connect_ep, auth_options);
}

TcpEndpointOrErrorAwait RunSecondBindStep(tcp::socket& socket) noexcept {
  co_return co_await RunSecondBindStepImpl(socket);
}

BytesCountOrErrorAwait RunSendTo(udp::socket& socket,
                                 const udp::endpoint& proxy_server_ep,
                                 const common::Address& target_server_addr,
                                 const char* data, size_t size) noexcept {
  co_return co_await RunSendToImpl(socket, proxy_server_ep, target_server_addr,
                                   data, size);
}

BytesCountOrErrorAwait RunReceiveFrom(udp::socket& socket,
                                      udp::endpoint& proxy_sender_ep,
                                      common::Address& sender_addr,
                                      common::DatagramBuffer& buf) noexcept {
  co_return co_await RunReceiveFromImpl(socket, proxy_sender_ep, sender_addr,
                                        buf);
}

}  // namespace socks5::client