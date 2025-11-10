#pragma once

#include <socks5/common/asio.hpp>
#include <net/utils.hpp>

namespace socks5::net {

template <typename Buffer>
ErrorAwait Send(tcp::socket& socket, const Buffer& buf) noexcept {
  const auto [err, _] = co_await asio::async_write(
      socket, asio::buffer(buf.BeginRead(), buf.ReadableBytes()),
      use_nothrow_awaitable);
  co_return err;
}

template <typename Buffer>
ErrorAwait Read(tcp::socket& socket, Buffer& buf, size_t len) noexcept {
  const auto [err, _] = co_await asio::async_read(
      socket, MakeAsioBuffer(buf, len), use_nothrow_awaitable);
  co_return err;
}

template <typename Buffer>
ErrorAwait ReadSome(tcp::socket& socket, Buffer& buf) noexcept {
  const auto [err, recv_bytes] = co_await socket.async_read_some(
      asio::buffer(buf.BeginWrite(), buf.WritableBytes()),
      use_nothrow_awaitable);
  buf.HasWritten(recv_bytes);
  co_return err;
}

template <typename Buffer>
ErrorAwait Read(udp::socket& socket, udp::endpoint& sender_ep,
                Buffer& buf) noexcept {
  const auto [err, recv_bytes] = co_await socket.async_receive_from(
      asio::buffer(buf.BeginWrite(), buf.WritableBytes()), sender_ep,
      use_nothrow_awaitable);
  buf.HasWritten(recv_bytes);
  co_return err;
}

template <typename Buffer>
UdpEndpointOrErrorAwait Read(udp::socket& socket, Buffer& buf) noexcept {
  udp::endpoint sender_ep;
  const auto err = co_await Read(socket, sender_ep, buf);
  co_return std::make_pair(std::move(err), std::move(sender_ep));
}

}  // namespace socks5::net