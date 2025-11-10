#include <boost/asio.hpp>
#include <fmt/core.h>
#include <cstdio>
#include <array>
#include <iostream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr size_t kEchoBufSize{1024};
constexpr unsigned short kServerPort{5555};

constexpr size_t kIPv4Size{4};

constexpr std::string_view kEchoMessage{
    "Echo message for an example of using a client and "
    "server on the libsocks library."};

std::string ToString(const tcp::endpoint& ep) {
  return fmt::format("ip={} port={}", ep.address().to_string(), ep.port());
}

template <size_t Size>
std::string_view ToString(const std::array<char, Size> data,
                          size_t len = Size) noexcept {
  return std::string_view{data.data(), len};
}

template <size_t Size>
void Print(std::string_view addr, const std::array<char, Size> data, size_t len,
           size_t n) {
  std::cout << n << ". Received from: " << addr
            << ", msg: " << ToString(data, len) << std::endl;
}

asio::awaitable<tcp::endpoint> ReadClientEpForIncomingConnect(
    tcp::socket& accepted_socket) {
  std::array<uint8_t, kIPv4Size> ipv4_buf;
  auto recv_bytes = co_await accepted_socket.async_read_some(
      asio::buffer(ipv4_buf), asio::use_awaitable);
  unsigned short port;
  recv_bytes = co_await accepted_socket.async_read_some(
      asio::buffer(&port, sizeof(port)), asio::use_awaitable);
  co_return tcp::endpoint{
      asio::ip::make_address_v4(ipv4_buf),
      asio::detail::socket_ops::network_to_host_short(port)};
}

asio::awaitable<void> EchoOnce(tcp::socket& client_socket,
                               std::string_view client_addr_str, size_t n) {
  std::array<char, kEchoBufSize> data;
  const auto recv_bytes = co_await client_socket.async_read_some(
      asio::buffer(data), asio::use_awaitable);
  Print(client_addr_str, data, recv_bytes, n);
  co_await asio::async_write(client_socket, asio::buffer(data, recv_bytes),
                             asio::use_awaitable);
}

asio::awaitable<void> Echo(tcp::socket client_socket,
                           tcp::endpoint client_ep) noexcept {
  try {
    co_await asio::async_write(
        client_socket, asio::buffer(kEchoMessage.data(), kEchoMessage.size()),
        asio::use_awaitable);
    const auto client_addr_str = ToString(client_ep);
    for (size_t i = 0;; ++i) {
      co_await EchoOnce(client_socket, client_addr_str, i);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (const std::exception& ex) {
    std::cerr << "Echo exception: " << ex.what() << std::endl;
  }
}

asio::awaitable<void> Listener() {
  auto executor = co_await asio::this_coro::executor;
  tcp::acceptor acceptor{executor,
                         {asio::ip::make_address("127.0.0.1"), kServerPort}};
  for (;;) {
    auto accepted_socket = co_await acceptor.async_accept(asio::use_awaitable);
    const auto client_ep_for_incomming_connect =
        co_await ReadClientEpForIncomingConnect(accepted_socket);
    tcp::socket client_socket{executor};
    co_await client_socket.async_connect(client_ep_for_incomming_connect,
                                         asio::use_awaitable);
    co_spawn(executor,
             Echo(std::move(client_socket),
                  std::move(client_ep_for_incomming_connect)),
             asio::detached);
  }
}

int main() {
  try {
    asio::io_context io_context{1};
    co_spawn(io_context, Listener(), asio::detached);
    io_context.run();
  } catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    return 1;
  }
  return 0;
}