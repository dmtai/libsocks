#include <net/utils.hpp>
#include <iostream>

namespace socks5::net {

namespace {

SocketOrErrorAwait ConnectByIP(const proto::Addr& addr) {
  const auto ep = MakeEndpointFromIP<tcp>(addr);
  tcp::socket socket{co_await asio::this_coro::executor};
  const auto [err] = co_await socket.async_connect(ep, use_nothrow_awaitable);
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(std::move(err), std::move(socket));
}

SocketOrErrorAwait ConnectByDomain(const proto::Addr& addr) {
  const auto [err, endpoints] = co_await Resolve<tcp>(addr.addr.domain);
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }

  tcp::socket socket{co_await asio::this_coro::executor};
  if (const auto [err, _] = co_await asio::async_connect(socket, *endpoints,
                                                         use_nothrow_awaitable);
      err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(std::move(err), std::move(socket));
}

SocketOrErrorAwait ConnectByIP(const proto::Addr& addr,
                               const tcp::endpoint& bind_ep) {
  try {
    const auto ep = MakeEndpointFromIP<tcp>(addr);
    tcp::socket socket{co_await asio::this_coro::executor};
    socket.open(bind_ep.protocol());
    socket.bind(bind_ep);
    const auto [err] = co_await socket.async_connect(ep, use_nothrow_awaitable);
    if (err) {
      std::cout << err.message() << std::endl;
      co_return std::make_pair(std::move(err), std::nullopt);
    }
    co_return std::make_pair(std::move(err), std::move(socket));
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
    co_return std::make_pair(boost::system::error_code{}, std::nullopt);
  }
}

SocketOrErrorAwait ConnectByDomain(const proto::Addr& addr,
                                   const tcp::endpoint& bind_ep) {
  const auto [err, endpoints] = co_await Resolve<tcp>(addr.addr.domain);
  if (err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }

  tcp::socket socket{co_await asio::this_coro::executor};
  socket.open(bind_ep.protocol());
  socket.bind(bind_ep);
  if (const auto [err, _] = co_await asio::async_connect(socket, *endpoints,
                                                         use_nothrow_awaitable);
      err) {
    co_return std::make_pair(std::move(err), std::nullopt);
  }
  co_return std::make_pair(std::move(err), std::move(socket));
}

}  // namespace

SocketOrErrorAwait Connect(const proto::Addr& addr) {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4:
    case proto::AddrType::kAddrTypeIPv6: {
      co_return co_await ConnectByIP(addr);
    }
    case proto::AddrType::kAddrTypeDomainName: {
      co_return co_await ConnectByDomain(addr);
    }
  }

  throw std::runtime_error("Unknown atyp for Connect");
}

SocketOrErrorAwait Connect(const proto::Addr& addr,
                           const tcp::endpoint& bind_ep) {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4:
    case proto::AddrType::kAddrTypeIPv6: {
      co_return co_await ConnectByIP(addr, bind_ep);
    }
    case proto::AddrType::kAddrTypeDomainName: {
      co_return co_await ConnectByDomain(addr, bind_ep);
    }
  }

  throw std::runtime_error("Unknown atyp for Connect");
}

}  // namespace socks5::net