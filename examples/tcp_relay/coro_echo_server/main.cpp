#include <boost/asio.hpp>
#include <fmt/core.h>
#include <cstdio>
#include <array>
#include <iostream>
#include <syncstream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr size_t kEchoBufSize{1024};
constexpr unsigned short kServerPort{5555};

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

asio::awaitable<void> EchoOnce(tcp::socket& socket, std::string_view addr,
                               size_t n) {
  std::array<char, kEchoBufSize> data;
  const auto recv_bytes =
      co_await socket.async_read_some(asio::buffer(data), asio::use_awaitable);
  Print(addr, data, recv_bytes, n);
  co_await asio::async_write(socket, asio::buffer(data, recv_bytes),
                             asio::use_awaitable);
}

asio::awaitable<void> Echo(tcp::socket socket) noexcept {
  const auto addr = ToString(socket.remote_endpoint());
  try {
    for (size_t i = 0;; ++i) {
      co_await EchoOnce(socket, addr, i);
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
    auto socket = co_await acceptor.async_accept(asio::use_awaitable);
    co_spawn(executor, Echo(std::move(socket)), asio::detached);
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