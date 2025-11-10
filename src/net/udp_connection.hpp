#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <utils/timeout.hpp>
#include <net/connection_error.hpp>

namespace socks5::net {

using UdpEndpointOrError = std::pair<UdpConnectErrorOpt, UdpEndpointOpt>;
using UdpEndpointOrErrorAwait = asio::awaitable<UdpEndpointOrError>;

class UdpConnection final : utils::NonCopyable {
 public:
  using LocalAddrString = std::string;
  using LocalAddrStrOpt = std::optional<LocalAddrString>;

  UdpConnection(udp::socket socket, common::Metrics& metrics) noexcept;

  udp::socket& GetSocket() noexcept;
  const udp::socket& GetSocket() const noexcept;
  void Stop() noexcept;
  UdpConnectErrorOptAwait Send(const udp::endpoint& ep, const char* data,
                               size_t data_size) noexcept;
  UdpConnectErrorOptAwait Send(const udp::endpoint& ep, const char* data,
                               size_t data_size, size_t tmo) noexcept;
  UdpConnectErrorOpt Cancel() noexcept;
  UdpEndpointOrError LocalEndpoint() noexcept;
  void SetLocalAddrStr() noexcept;
  const LocalAddrString& LocalAddrStr() noexcept;

  template <typename Buffer>
  UdpEndpointOrErrorAwait Read(Buffer& buf) noexcept {
    udp::endpoint sender_ep;
    const auto [err, recv_bytes] = co_await socket_.async_receive_from(
        asio::buffer(buf.BeginWrite(), buf.WritableBytes()), sender_ep,
        use_nothrow_awaitable);
    buf.HasWritten(recv_bytes);
    metrics_.AddRecvBytes(recv_bytes);
    if (err) {
      co_return std::make_pair(
          MakeError("Error receiving from UDP socket", err), std::nullopt);
    }
    co_return std::make_pair(std::nullopt, std::move(sender_ep));
  }

  template <typename Buffer>
  UdpEndpointOrErrorAwait Read(Buffer& buf, size_t tmo) noexcept {
    try {
      const auto recv_res = co_await (Read(buf) || utils::Timeout(tmo));
      if (recv_res.index() == 1) {
        co_return std::make_pair(
            MakeError("UDP socket receive timeout expired"), std::nullopt);
      }
      co_return std::get<0>(recv_res);
    } catch (const std::exception&) {
      co_return std::make_pair(
          MakeError("Exception while receiving from UDP socket",
                    std::current_exception()),
          std::nullopt);
    }
  }

  template <typename Buffer>
  UdpConnectErrorOptAwait Send(const udp::endpoint& ep,
                               const Buffer& buf) noexcept {
    co_return co_await Send(ep, buf.BeginRead(), buf.ReadableBytes());
  }

  template <typename Buffer>
  UdpConnectErrorOptAwait Send(const udp::endpoint& ep, const Buffer& buf,
                               size_t tmo) noexcept {
    try {
      const auto send_res = co_await (Send(ep, buf) || utils::Timeout(tmo));
      if (send_res.index() == 1) {
        co_return MakeError("UDP socket send timeout expired");
      }
      co_return std::get<0>(send_res);
    } catch (const std::exception&) {
      co_return MakeError("Exception while sending to UDP socket",
                          std::current_exception());
    }
  }

  template <size_t ArrSize>
  UdpConnectErrorOptAwait Send(
      const udp::endpoint& ep,
      const std::array<asio::const_buffer, ArrSize>& buffs) noexcept {
    const auto [err, sent_bytes] =
        co_await socket_.async_send_to(buffs, ep, use_nothrow_awaitable);
    metrics_.AddSentBytes(sent_bytes);
    if (err) {
      co_return MakeError("Error sending to UDP socket", err);
    }
    co_return std::nullopt;
  }

 private:
  udp::socket socket_;
  common::Metrics& metrics_;
  LocalAddrStrOpt local_addr_;
};

UdpConnection MakeUdpConnect(udp::socket socket,
                             common::Metrics& metrics) noexcept;
const std::string& ToString(UdpConnection& connect) noexcept;

}  // namespace socks5::net