#pragma once

#include <socks5/common/asio.hpp>
#include <proto/proto.hpp>
#include <common/addr_utils.hpp>
#include <socks5/error/error.hpp>
#include <socks5/utils/buffer.hpp>
#include <net/connection_error.hpp>

namespace socks5::net {

using SocketOrError = utils::ErrorOr<SocketOpt>;
using SocketOrErrorAwait = asio::awaitable<SocketOrError>;

template <typename... Ts>
void Stop(Ts&&... sockets) noexcept {
  (
      [&] {
        try {
          boost::system::error_code ec;
          sockets.shutdown(tcp::socket::shutdown_both, ec);
          sockets.close(ec);
        } catch (const std::exception&) {
        }
      }(),
      ...);
}

template <typename... Ts>
void StopConnections(Ts&&... connections) noexcept {
  ([&] { connections.Stop(); }(), ...);
}

SocketOrErrorAwait Connect(const proto::Addr& addr);
SocketOrErrorAwait Connect(const proto::Addr& addr,
                           const tcp::endpoint& bind_ep);

template <typename T>
EndpointsOrErrorAwait<T> Resolve(const proto::Domain& domain) noexcept {
  try {
    typename T::resolver resolver{co_await asio::this_coro::executor};
    std::array<char, 6> port_buf{};
    std::to_chars(port_buf.data(), port_buf.data() + port_buf.size(),
                  asio::detail::socket_ops::network_to_host_short(domain.port));
    typename T::resolver::query query{
        {reinterpret_cast<const char*>(domain.addr.data()), domain.length},
        port_buf.data()};
    const auto [err, endpoints] =
        co_await resolver.async_resolve(query, use_nothrow_awaitable);
    if (err) {
      co_return std::make_pair(std::move(err), std::nullopt);
    }
    co_return std::make_pair(std::move(err), std::move(endpoints));
  } catch (...) {
    co_return std::make_pair(error::Error::kDomainResolutionFailure,
                             std::nullopt);
  }
}

template <typename T>
T::socket MakeOpenSocket(const asio::any_io_executor& executor,
                         const std::string& addr, unsigned short port) {
  return typename T::socket{
      executor,
      typename T::endpoint{asio::ip::address::from_string(addr), port}};
}

template <typename T>
T::endpoint MakeEndpointFromIP(const proto::Addr& addr) noexcept {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      return typename T::endpoint{
          asio::ip::make_address_v4(addr.addr.ipv4.addr),
          asio::detail::socket_ops::network_to_host_short(addr.addr.ipv4.port)};
    }
    case proto::AddrType::kAddrTypeIPv6: {
      return typename T::endpoint{
          asio::ip::make_address_v6(addr.addr.ipv6.addr),
          asio::detail::socket_ops::network_to_host_short(addr.addr.ipv6.port)};
    }
  }
  return typename T::endpoint{};
}

template <typename T>
EndpointsOrErrorAwait<T> MakeEndpointsFromDomain(
    const proto::Addr& addr) noexcept {
  if (addr.atyp != proto::AddrType::kAddrTypeDomainName) {
    co_return std::make_pair(error::Error::kAddressTypeNotSupported,
                             std::nullopt);
  }
  const auto [err, endpoints] = co_await Resolve<T>(addr.addr.domain);
  typename T::resolver::iterator end;
  if (err || *endpoints == end) {
    co_return std::make_pair(error::Error::kAddressTypeNotSupported,
                             std::nullopt);
  }
  co_return std::make_pair(error::Error::kSucceeded, endpoints);
}

template <typename T>
EndpointOrErrorAwait<T> MakeEndpoint(const proto::Addr& addr) noexcept {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4:
    case proto::AddrType::kAddrTypeIPv6: {
      co_return std::make_pair(error::Error::kSucceeded,
                               MakeEndpointFromIP<T>(addr));
    }
    case proto::AddrType::kAddrTypeDomainName: {
      const auto [err, endpoints] = co_await MakeEndpointsFromDomain<T>(addr);
      if (err) {
        co_return std::make_pair(std::move(err), std::nullopt);
      }
      co_return std::make_pair(error::Error::kSucceeded,
                               std::move(**endpoints));
    }
  }
  co_return std::make_pair(error::Error::kAddressTypeNotSupported,
                           std::nullopt);
}

template <size_t Size>
auto MakeAsioBuffer(utils::StaticBuffer<Size>& buf,
                    size_t len = Size) noexcept {
  auto asio_buf = asio::buffer(buf.BeginWrite(), len);
  buf.HasWritten(len);
  return asio_buf;
}

template <typename T>
std::string ToString(const typename T::endpoint& ep) {
  const auto addr = ep.address();
  if (addr.is_v6()) {
    return fmt::format("[{}]:{}", addr.to_string(), ep.port());
  } else {
    return fmt::format("{}:{}", addr.to_string(), ep.port());
  }
}

enum class EndpointType {
  kRemoteEndpoint,
  kLocalEndpoint,
};

template <typename T>
std::string ToString(const typename T::socket& socket,
                     EndpointType ep_type = EndpointType::kRemoteEndpoint) {
  const auto ep = ep_type == EndpointType::kRemoteEndpoint
                      ? socket.remote_endpoint()
                      : socket.local_endpoint();

  return ToString<T>(ep);
}

}  // namespace socks5::net