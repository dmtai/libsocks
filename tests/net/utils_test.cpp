#include <gtest/gtest.h>
#include <net/utils.hpp>
#include <common/addr_utils.hpp>
#include <socks5/common/asio.hpp>
#include <net/connection_error.hpp>
#include <socks5/utils/buffer.hpp>
#include <socks5/utils/type_traits.hpp>

namespace socks5::net {

namespace {

proto::Addr MakeIPv4Addr(const std::string& ip, unsigned short port) {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeIPv4;
  auto addr_v4 = asio::ip::make_address_v4(ip).to_bytes();
  std::copy(addr_v4.begin(), addr_v4.end(), addr.addr.ipv4.addr.begin());
  addr.addr.ipv4.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

proto::Addr MakeIPv6Addr(const std::string& ip, unsigned short port) {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeIPv6;
  auto addr_v6 = asio::ip::make_address_v6(ip).to_bytes();
  std::copy(addr_v6.begin(), addr_v6.end(), addr.addr.ipv6.addr.begin());
  addr.addr.ipv6.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

proto::Addr MakeDomainAddr(const std::string& domain, unsigned short port) {
  proto::Addr addr;
  addr.atyp = proto::AddrType::kAddrTypeDomainName;
  addr.addr.domain.length = static_cast<uint8_t>(domain.size());
  std::copy(domain.begin(), domain.end(), addr.addr.domain.addr.begin());
  addr.addr.domain.port = asio::detail::socket_ops::host_to_network_short(port);
  return addr;
}

class NetUtilsTest : public ::testing::Test {
 protected:
  asio::io_context io_;
};

}  // namespace

TEST_F(NetUtilsTest, ConnectIPv4Success) {
  auto coro = [this]() -> asio::awaitable<void> {
    auto executor = co_await asio::this_coro::executor;

    tcp::acceptor acceptor{
        executor, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)};
    const auto port = acceptor.local_endpoint().port();

    tcp::socket server_socket{executor};
    boost::system::error_code accept_ec;
    acceptor.async_accept(server_socket,
                          [&](const auto& ec) { accept_ec = ec; });

    const auto addr = MakeIPv4Addr("127.0.0.1", port);
    auto [connect_ec, socket_opt] = co_await socks5::net::Connect(addr);

    EXPECT_FALSE(connect_ec) << "Connect error: " << connect_ec.message();
    EXPECT_TRUE(socket_opt.has_value());

    if (socket_opt) {
      socket_opt->close();
    }
    server_socket.close();
    acceptor.close();
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, ConnectDomainSuccess) {
  auto coro = [this]() -> asio::awaitable<void> {
    auto executor = co_await asio::this_coro::executor;

    tcp::acceptor acceptor{
        executor, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)};
    const auto port = acceptor.local_endpoint().port();

    tcp::socket server_socket{executor};
    boost::system::error_code accept_ec;
    acceptor.async_accept(server_socket,
                          [&](const auto& ec) { accept_ec = ec; });

    const auto addr = MakeDomainAddr("localhost", port);
    auto [connect_ec, socket_opt] = co_await socks5::net::Connect(addr);

    EXPECT_FALSE(connect_ec) << "Connect error: " << connect_ec.message();
    EXPECT_TRUE(socket_opt.has_value());

    if (socket_opt) {
      socket_opt->close();
    }
    server_socket.close();
    acceptor.close();
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, ConnectIPv4Error) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeIPv4Addr("127.0.0.1", 1);
    const auto [connect_ec, socket_opt] = co_await socks5::net::Connect(addr);

    EXPECT_TRUE(connect_ec);
    EXPECT_FALSE(socket_opt.has_value());
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, ConnectDomainError) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeDomainAddr("invalid.domain.that.does.not.exist", 1);
    const auto [connect_ec, socket_opt] = co_await socks5::net::Connect(addr);

    EXPECT_TRUE(connect_ec);
    EXPECT_FALSE(socket_opt.has_value());
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, ConnectUnknownAddrType) {
  auto coro = [this]() -> asio::awaitable<void> {
    proto::Addr addr;
    addr.atyp = static_cast<proto::AddrType>(0xFF);

    try {
      co_await socks5::net::Connect(addr);
      ADD_FAILURE() << "Expected std::runtime_error";
    } catch (const std::runtime_error& ex) {
      EXPECT_STREQ(ex.what(), "Unknown atyp for Connect");
    } catch (...) {
      ADD_FAILURE() << "Unexpected exception type";
    }
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, StopFunction) {
  tcp::socket socket1{io_};
  tcp::socket socket2{io_};

  socket1.open(tcp::v4());
  socket2.open(tcp::v4());

  EXPECT_TRUE(socket1.is_open());
  EXPECT_TRUE(socket2.is_open());

  Stop(socket1, socket2);

  EXPECT_FALSE(socket1.is_open());
  EXPECT_FALSE(socket2.is_open());
}

TEST_F(NetUtilsTest, ResolveSuccess) {
  auto coro = [this]() -> asio::awaitable<void> {
    proto::Domain domain;
    domain.length = 9;
    std::memcpy(domain.addr.data(), "localhost", 9);
    domain.port = asio::detail::socket_ops::host_to_network_short(80);

    const auto [err, endpoints] = co_await Resolve<tcp>(domain);
    EXPECT_FALSE(err) << "Resolve error: " << err.message();
    EXPECT_TRUE(endpoints.has_value());
    EXPECT_GT(endpoints->size(), 0);
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, ResolveFailure) {
  auto coro = [this]() -> asio::awaitable<void> {
    proto::Domain domain;
    domain.length = 28;
    std::memcpy(domain.addr.data(), "invalid.domain.that.does.not.exist", 28);
    domain.port = asio::detail::socket_ops::host_to_network_short(80);

    const auto [err, endpoints] = co_await Resolve<tcp>(domain);
    EXPECT_TRUE(err);
    EXPECT_FALSE(endpoints.has_value());
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, MakeOpenSocketIPv4) {
  auto socket = MakeOpenSocket<tcp>(io_.get_executor(), "127.0.0.1", 8080);
  EXPECT_TRUE(socket.is_open());
  EXPECT_EQ(socket.local_endpoint().address().to_string(), "127.0.0.1");
  EXPECT_EQ(socket.local_endpoint().port(), 8080);
  socket.close();
}

TEST_F(NetUtilsTest, MakeOpenSocketIPv6) {
  if (asio::ip::make_address_v6("::1").is_loopback()) {
    auto socket = MakeOpenSocket<tcp>(io_.get_executor(), "::1", 8080);
    EXPECT_TRUE(socket.is_open());
    EXPECT_EQ(socket.local_endpoint().address().to_string(), "::1");
    EXPECT_EQ(socket.local_endpoint().port(), 8080);
    socket.close();
  } else {
    GTEST_SKIP() << "IPv6 not supported";
  }
}

TEST_F(NetUtilsTest, MakeEndpointFromIPv4) {
  const auto addr = MakeIPv4Addr("192.168.1.1", 8080);
  const auto endpoint = MakeEndpointFromIP<tcp>(addr);

  EXPECT_EQ(endpoint.address().to_string(), "192.168.1.1");
  EXPECT_EQ(endpoint.port(), 8080);
}

TEST_F(NetUtilsTest, MakeEndpointFromIPv6) {
  const auto addr = MakeIPv6Addr("2001:db8::1", 8080);
  const auto endpoint = MakeEndpointFromIP<tcp>(addr);

  EXPECT_EQ(endpoint.address().to_string(), "2001:db8::1");
  EXPECT_EQ(endpoint.port(), 8080);
}

TEST_F(NetUtilsTest, MakeEndpointsFromDomainSuccess) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeDomainAddr("localhost", 80);
    const auto [err, endpoints] = co_await MakeEndpointsFromDomain<tcp>(addr);

    EXPECT_FALSE(err);
    EXPECT_TRUE(endpoints.has_value());
    EXPECT_GT(endpoints->size(), 0);
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, MakeEndpointsFromDomainInvalidType) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeIPv4Addr("127.0.0.1", 80);
    const auto [err, endpoints] = co_await MakeEndpointsFromDomain<tcp>(addr);

    EXPECT_TRUE(err);
    EXPECT_EQ(err, error::Error::kAddressTypeNotSupported);
    EXPECT_FALSE(endpoints.has_value());
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, MakeEndpointIPv4) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeIPv4Addr("127.0.0.1", 8080);
    const auto [err, endpoint] = co_await MakeEndpoint<tcp>(addr);

    EXPECT_FALSE(err);
    EXPECT_TRUE(endpoint.has_value());
    EXPECT_EQ(endpoint->address().to_string(), "127.0.0.1");
    EXPECT_EQ(endpoint->port(), 8080);
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, MakeEndpointDomain) {
  auto coro = [this]() -> asio::awaitable<void> {
    const auto addr = MakeDomainAddr("localhost", 8080);
    const auto [err, endpoint] = co_await MakeEndpoint<tcp>(addr);

    EXPECT_FALSE(err);
    EXPECT_TRUE(endpoint.has_value());
    EXPECT_TRUE(endpoint->address().is_loopback());
    EXPECT_EQ(endpoint->port(), 8080);
  };

  auto fut = asio::co_spawn(io_, coro(), asio::use_future);
  io_.run();
  EXPECT_NO_THROW(fut.get());
}

TEST_F(NetUtilsTest, MakeAsioBuffer) {
  utils::StaticBuffer<1024> buf;
  const std::string test_data{"Hello, world!"};
  std::memcpy(buf.BeginWrite(), test_data.data(), test_data.size());
  buf.HasWritten(test_data.size());

  auto asio_buf = MakeAsioBuffer(buf, test_data.size());

  EXPECT_EQ(asio::buffer_size(asio_buf), test_data.size());
  EXPECT_EQ(buf.ReadableBytes(), test_data.size() * 2);
  EXPECT_EQ(std::string(buf.BeginRead(), test_data.size()), test_data);
}

TEST_F(NetUtilsTest, ToStringEndpoint) {
  const auto endpoint =
      tcp::endpoint(asio::ip::make_address("192.168.1.1"), 8080);
  const auto result = ToString<tcp>(endpoint);
  EXPECT_EQ(result, "192.168.1.1:8080");
}

TEST_F(NetUtilsTest, ToStringSocket) {
  tcp::socket socket{io_};
  asio::ip::tcp::acceptor acceptor(
      io_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
  const auto port = acceptor.local_endpoint().port();

  auto coro = [&]() -> asio::awaitable<void> {
    co_await acceptor.async_accept(socket, asio::use_awaitable);
  };

  auto accept_fut = asio::co_spawn(io_, coro(), asio::use_future);

  tcp::socket client{io_};
  client.connect(acceptor.local_endpoint());

  io_.restart();
  io_.run();

  const auto local_str = ToString<tcp>(socket, EndpointType::kLocalEndpoint);
  const auto remote_str = ToString<tcp>(socket, EndpointType::kRemoteEndpoint);

  EXPECT_NE(local_str.find(fmt::format(":{}", port)), std::string::npos);
  EXPECT_NE(remote_str.find("127.0.0.1"), std::string::npos);
  EXPECT_NE(remote_str.find(fmt::format(":{}", client.local_endpoint().port())),
            std::string::npos);

  client.close();
  socket.close();
  acceptor.close();
}

}  // namespace socks5::net
