#include <net/tcp_connection.hpp>

namespace socks5::net {

TcpConnection MakeTcpConnect(tcp::socket socket,
                             common::Metrics& metrics) noexcept {
  return TcpConnection{std::move(socket), metrics};
}

const std::string& ToString(TcpConnection& connect) noexcept {
  return connect.RemoteAddrStr();
}

TcpConnection::TcpConnection(tcp::socket socket,
                             common::Metrics& metrics) noexcept
    : socket_{std::move(socket)}, metrics_{metrics} {}

TcpEndpointOrError TcpConnection::RemoteEndpoint() noexcept {
  boost::system::error_code err;
  const auto ep = socket_.remote_endpoint(err);
  if (err) {
    return std::make_pair(MakeError("Remote endpoint error", err),
                          std::nullopt);
  }
  return std::make_pair(std::nullopt, std::move(ep));
}

TcpEndpointOrError TcpConnection::LocalEndpoint() noexcept {
  boost::system::error_code err;
  const auto ep = socket_.local_endpoint(err);
  if (err) {
    return std::make_pair(MakeError("Local endpoint error", err), std::nullopt);
  }
  return std::make_pair(std::nullopt, std::move(ep));
}

TcpConnectErrorOptAwait TcpConnection::Send(const char* data,
                                            size_t size) noexcept {
  if (slot_) {
    co_return co_await Send(
        data, size,
        asio::bind_cancellation_slot(*slot_, use_nothrow_awaitable));
  }
  co_return co_await Send(data, size, use_nothrow_awaitable);
}

TcpConnectErrorOptAwait TcpConnection::Send(const char* data, size_t size,
                                            size_t tmo) noexcept {
  try {
    const auto send_res = co_await (Send(data, size) || utils::Timeout(tmo));
    if (send_res.index() == 1) {
      co_return MakeError("TCP socket write timeout expired");
    }
    co_return std::get<0>(send_res);
  } catch (const std::exception&) {
    co_return MakeError("Exception while writing to TCP socket",
                        std::current_exception());
  }
}

tcp::socket& TcpConnection::GetSocket() noexcept { return socket_; }

const tcp::socket& TcpConnection::GetSocket() const noexcept { return socket_; }

void TcpConnection::Stop() noexcept { net::Stop(socket_); }

void TcpConnection::SetCancellationSlot(CancellationSlot slot) noexcept {
  slot_ = std::move(slot);
}

void TcpConnection::ResetCancellationSlot() noexcept { slot_ = std::nullopt; }

void TcpConnection::SetRemoteAddrStr() noexcept {
  const auto [err, ep] = RemoteEndpoint();
  if (err) {
    remote_addr_ = err->Msg();
    return;
  }
  try {
    remote_addr_ = net::ToString<tcp>(*ep);
  } catch (const std::exception& ex) {
    remote_addr_ = ex.what();
  }
}

const TcpConnection::RemoteAddrString& TcpConnection::RemoteAddrStr() noexcept {
  if (remote_addr_) {
    return *remote_addr_;
  }
  SetRemoteAddrStr();
  return *remote_addr_;
}

}  // namespace socks5::net