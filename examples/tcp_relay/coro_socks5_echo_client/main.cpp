#include <boost/asio.hpp>
#include <socks5/client/client.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <iostream>
#include <chrono>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::string_view kProxyServerIP{"127.0.0.1"};
constexpr unsigned short kProxyServerPort{1080};

constexpr std::string_view kTargetEchoServerIP{"127.0.0.1"};
constexpr unsigned short kTargetEchoServerPort{5555};

constexpr size_t kTimeout{61440};
constexpr size_t kEchoBufSize{1024};

constexpr std::string_view kEchoMessage{
    "Echo message for an example of using a client and "
    "server on the libsocks library."};

template <size_t Size>
std::string_view ToString(const std::array<char, Size> data,
                          size_t len = Size) noexcept {
  return std::string_view{data.data(), len};
}

template <size_t Size>
void Print(const std::array<char, Size> data, size_t len, size_t n) {
  std::cout << n << ". Received: " << ToString(data, len) << std::endl;
}

asio::awaitable<boost::system::error_code> Connect(tcp::socket& socket) {
  tcp::endpoint proxy_server_ep{asio::ip::make_address_v4(kProxyServerIP),
                                kProxyServerPort};
  tcp::endpoint target_server_ep{asio::ip::make_address_v4(kTargetEchoServerIP),
                                 kTargetEchoServerPort};

  // Select an authentication method for the socks5 proxy.
  auto auth_options = socks5::auth::client::MakeAuthOptions();
  auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kNone>();
  // or
  // auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kUser>("user",
  // "password"); for username/password authentication.

  // Connect asynchronously to the target server via the socks5 proxy using
  // libsocks.
  co_return co_await socks5::client::AsyncConnect(
      socket, proxy_server_ep, socks5::common::Address{target_server_ep},
      auth_options, kTimeout);
}

asio::awaitable<void> EchoOnce(tcp::socket& socket, size_t n) {
  std::array<char, kEchoBufSize> data;
  const auto recv_bytes =
      co_await socket.async_read_some(asio::buffer(data), asio::use_awaitable);
  Print(data, recv_bytes, n);
  co_await asio::async_write(socket, asio::buffer(data, recv_bytes),
                             asio::use_awaitable);
}

asio::awaitable<void> Echo() noexcept {
  try {
    tcp::socket socket{co_await asio::this_coro::executor};
    const auto err = co_await Connect(socket);
    if (err) {
      std::cerr << err.message() << std::endl;
      co_return;
    }
    co_await asio::async_write(
        socket, asio::buffer(kEchoMessage.data(), kEchoMessage.size()),
        asio::use_awaitable);
    for (size_t i = 0;; ++i) {
      co_await EchoOnce(socket, i);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (const std::exception& ex) {
    std::cerr << "Echo exception: " << ex.what() << std::endl;
  }
}

int main() {
  try {
    asio::io_context io_context{1};
    co_spawn(io_context, Echo(), asio::detached);
    io_context.run();
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    return 1;
  }
}