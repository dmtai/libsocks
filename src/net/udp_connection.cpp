#include <net/udp_connection.hpp>
#include <common/addr_utils.hpp>
#include <net/utils.hpp>

namespace socks5::net {

UdpConnection MakeUdpConnect(udp::socket socket,
                             common::Metrics& metrics) noexcept {
  return UdpConnection{std::move(socket), metrics};
}

const std::string& ToString(UdpConnection& connect) noexcept {
  return connect.LocalAddrStr();
}

UdpConnection::UdpConnection(udp::socket socket,
                             common::Metrics& metrics) noexcept
    : socket_{std::move(socket)}, metrics_{metrics} {}

udp::socket& UdpConnection::GetSocket() noexcept { return socket_; }

const udp::socket& UdpConnection::GetSocket() const noexcept { return socket_; }

void UdpConnection::Stop() noexcept { net::Stop(socket_); }

UdpConnectErrorOptAwait UdpConnection::Send(const udp::endpoint& ep,
                                            const char* data,
                                            size_t data_size) noexcept {
  const auto [err, sent_bytes] = co_await socket_.async_send_to(
      asio::buffer(data, data_size), ep, use_nothrow_awaitable);
  metrics_.AddSentBytes(sent_bytes);
  if (err) {
    co_return MakeError("Error sending to UDP socket", err);
  }
  co_return std::nullopt;
}

UdpConnectErrorOptAwait UdpConnection::Send(const udp::endpoint& ep,
                                            const char* data, size_t data_size,
                                            size_t tmo) noexcept {
  try {
    const auto send_res =
        co_await (Send(ep, data, data_size) || utils::Timeout(tmo));
    if (send_res.index() == 1) {
      co_return MakeError("UDP socket send timeout expired");
    }
    co_return std::get<0>(send_res);
  } catch (const std::exception&) {
    co_return MakeError("Exception while sending to UDP socket",
                        std::current_exception());
  }
}

UdpConnectErrorOpt UdpConnection::Cancel() noexcept {
  try {
    boost::system::error_code err;
    socket_.cancel(err);
    if (err) {
      return MakeError("UDP socket cancellation error", err);
    }
    return std::nullopt;
  } catch (const std::exception&) {
    return MakeError("UDP socket cancellation exception",
                     std::current_exception());
  }
}

UdpEndpointOrError UdpConnection::LocalEndpoint() noexcept {
  boost::system::error_code err;
  const auto ep = socket_.local_endpoint(err);
  if (err) {
    return std::make_pair(MakeError("Local endpoint error", err), std::nullopt);
  }
  return std::make_pair(std::nullopt, std::move(ep));
}

void UdpConnection::SetLocalAddrStr() noexcept {
  const auto [err, ep] = LocalEndpoint();
  if (err) {
    local_addr_ = err->Msg();
    return;
  }
  try {
    local_addr_ = net::ToString<udp>(*ep);
  } catch (const std::exception& ex) {
    local_addr_ = ex.what();
  }
}

const UdpConnection::LocalAddrString& UdpConnection::LocalAddrStr() noexcept {
  if (local_addr_) {
    return *local_addr_;
  }
  SetLocalAddrStr();
  return *local_addr_;
}

}  // namespace socks5::net