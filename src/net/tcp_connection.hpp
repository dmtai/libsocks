#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <utils/timeout.hpp>
#include <common/addr_utils.hpp>
#include <net/connection_error.hpp>
#include <net/utils.hpp>

namespace socks5::net {

using TcpEndpointOrError = std::pair<TcpConnectErrorOpt, TcpEndpointOpt>;

class TcpConnection final : utils::NonCopyable {
 public:
  using RemoteAddrString = std::string;
  using RemoteAddrStrOpt = std::optional<RemoteAddrString>;

  TcpConnection(tcp::socket socket, common::Metrics& metrics) noexcept;

  TcpConnectErrorOptAwait Send(const char* data, size_t size) noexcept;
  TcpConnectErrorOptAwait Send(const char* data, size_t size,
                               size_t tmo) noexcept;
  TcpEndpointOrError RemoteEndpoint() noexcept;
  TcpEndpointOrError LocalEndpoint() noexcept;
  tcp::socket& GetSocket() noexcept;
  const tcp::socket& GetSocket() const noexcept;
  void Stop() noexcept;
  void SetCancellationSlot(CancellationSlot slot) noexcept;
  void ResetCancellationSlot() noexcept;
  void SetRemoteAddrStr() noexcept;
  const RemoteAddrString& RemoteAddrStr() noexcept;

  template <class Buffer, class CompletionToken>
    requires asio::completion_token_for<
        CompletionToken, void(boost::system::error_code, std::size_t)>
  TcpConnectErrorOptAwait Read(Buffer& buf, size_t len,
                               CompletionToken&& token) noexcept {
    const auto [err, recv_bytes] =
        co_await asio::async_read(socket_, MakeAsioBuffer(buf, len), token);
    metrics_.AddRecvBytes(recv_bytes);
    if (err) {
      co_return MakeError("Error reading from TCP socket", err);
    }
    co_return std::nullopt;
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait Read(Buffer& buf, size_t len) noexcept {
    if (slot_) {
      co_return co_await Read(
          buf, len,
          asio::bind_cancellation_slot(*slot_, use_nothrow_awaitable));
    }
    co_return co_await Read(buf, len, use_nothrow_awaitable);
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait Read(Buffer& buf, size_t len, size_t tmo) noexcept {
    try {
      const auto recv_res = co_await (Read(buf, len) || utils::Timeout(tmo));
      if (recv_res.index() == 1) {
        co_return MakeError("TCP socket read timeout expired");
      }
      co_return std::get<0>(recv_res);
    } catch (const std::exception&) {
      co_return MakeError("Exception while reading from TCP socket",
                          std::current_exception());
    }
  }

  template <typename Buffer, typename Token>
  TcpConnectErrorOptAwait ReadSome(Buffer& buf, Token&& token) noexcept {
    const auto [err, recv_bytes] = co_await socket_.async_read_some(
        asio::buffer(buf.BeginWrite(), buf.WritableBytes()), token);
    buf.HasWritten(recv_bytes);
    metrics_.AddRecvBytes(recv_bytes);
    if (err) {
      co_return MakeError("Error reading from TCP socket", err);
    }
    co_return std::nullopt;
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait ReadSome(Buffer& buf) noexcept {
    if (slot_) {
      co_return co_await ReadSome(
          buf, asio::bind_cancellation_slot(*slot_, use_nothrow_awaitable));
    }
    co_return co_await ReadSome(buf, use_nothrow_awaitable);
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait ReadSome(Buffer& buf, size_t tmo) noexcept {
    try {
      const auto recv_res = co_await (ReadSome(buf) || utils::Timeout(tmo));
      if (recv_res.index() == 1) {
        co_return MakeError("TCP socket read timeout expired");
      }
      co_return std::get<0>(recv_res);
    } catch (const std::exception&) {
      co_return MakeError("Exception while reading from TCP socket",
                          std::current_exception());
    }
  }

  template <typename CompletionToken>
    requires asio::completion_token_for<
        CompletionToken, void(boost::system::error_code, std::size_t)>
  TcpConnectErrorOptAwait Send(const char* data, size_t size,
                               CompletionToken&& token) noexcept {
    try {
      const auto [err, sent_bytes] =
          co_await asio::async_write(socket_, asio::buffer(data, size), token);
      metrics_.AddSentBytes(sent_bytes);
      if (err) {
        co_return MakeError("Error writing to TCP socket", err);
      }
      co_return std::nullopt;
    } catch (const std::exception&) {
      co_return MakeError("Exception while writing to TCP socket",
                          std::current_exception());
    }
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait Send(const Buffer& buf) noexcept {
    co_return co_await Send(buf.BeginRead(), buf.ReadableBytes());
  }

  template <typename Buffer>
  TcpConnectErrorOptAwait Send(const Buffer& buf, size_t tmo) noexcept {
    co_return co_await Send(buf.BeginRead(), buf.ReadableBytes(), tmo);
  }

 private:
  tcp::socket socket_;
  common::Metrics& metrics_;
  CancellationSlotOpt slot_;
  RemoteAddrStrOpt remote_addr_;
};

TcpConnection MakeTcpConnect(tcp::socket socket,
                             common::Metrics& metrics) noexcept;
const std::string& ToString(TcpConnection& connect) noexcept;

}  // namespace socks5::net