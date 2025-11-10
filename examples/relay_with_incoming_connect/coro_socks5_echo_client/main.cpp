#include <boost/asio.hpp>
#include <socks5/client/client.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <iostream>
#include <chrono>
#include <fmt/core.h>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::string_view kProxyServerIP{"127.0.0.1"};
constexpr unsigned short kProxyServerPort{1080};

constexpr std::string_view kTargetEchoServerIP{"127.0.0.1"};
constexpr unsigned short kTargetEchoServerPort{5555};

constexpr size_t kTimeout{61440};
constexpr size_t kEchoBufSize{1024};

std::string ToString(const tcp::endpoint& ep) {
  return fmt::format("ip={} port={}", ep.address().to_string(), ep.port());
}

template <size_t Size>
std::string_view ToString(const std::array<char, Size> data,
                          size_t len = Size) noexcept {
  return std::string_view{data.data(), len};
}

template <size_t Size>
void Print(const std::array<char, Size> data, size_t len, size_t n) {
  std::cout << n << ". Received: " << ToString(data, len) << std::endl;
}

std::array<char, 6> Serialize(const tcp::endpoint& ep) {
  const auto ipv4_bytes = ep.address().to_v4().to_bytes();
  const auto port = ep.port();
  std::array<char, 6> result;
  std::memcpy(result.data(), ipv4_bytes.data(), ipv4_bytes.size());
  std::memcpy(result.data() + ipv4_bytes.size(), &port, sizeof(port));
  return result;
}

asio::awaitable<boost::system::error_code> Connect(
    tcp::socket& socket, const tcp::endpoint& proxy_server_ep,
    const tcp::endpoint& target_server_ep,
    const socks5::auth::client::AuthOptions& auth_options) {
  // Asynchronous connection to the target server via the socks5 proxy using
  // libsocks.
  co_return co_await socks5::client::AsyncConnect(
      socket, proxy_server_ep, socks5::common::Address{target_server_ep},
      auth_options, kTimeout);
}

asio::awaitable<void> Bind(tcp::socket& bind_socket) {
  tcp::endpoint proxy_server_ep{asio::ip::make_address_v4(kProxyServerIP),
                                kProxyServerPort};
  tcp::endpoint target_server_ep{asio::ip::make_address_v4(kTargetEchoServerIP),
                                 kTargetEchoServerPort};

  // Select an authentication method for the socks5 proxy.
  auto auth_options = socks5::auth::client::MakeAuthOptions();
  auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kNone>();

  tcp::socket connect_socket{co_await asio::this_coro::executor};
  // Establish a TCP connection to the target server via the socks5 proxy.
  const auto connect_err = co_await Connect(connect_socket, proxy_server_ep,
                                            target_server_ep, auth_options);
  if (connect_err) {
    std::cerr << connect_err.message() << std::endl;
    co_return;
  }

  // Send a BIND request to the socks5 proxy and get the address that the target
  // server will use to establish the connection.
  auto [incoming_connect_ep_err, incoming_connect_ep] =
      co_await socks5::client::FirstBindStep(bind_socket, proxy_server_ep,
                                             target_server_ep, auth_options,
                                             kTimeout);
  if (incoming_connect_ep_err) {
    std::cerr << incoming_connect_ep_err.message() << std::endl;
    co_return;
  }
  // Send the incoming connection address on the proxy to the target server.
  const auto incoming_connect_addr_bytes = Serialize(*incoming_connect_ep);
  co_await asio::async_write(connect_socket,
                             asio::buffer(incoming_connect_addr_bytes),
                             asio::use_awaitable);
  // Wait for the target server to connect to the socks5 proxy server.
  auto [accepted_ep_err, accepted_ep] =
      co_await socks5::client::SecondBindStep(bind_socket, kTimeout);
  if (accepted_ep_err) {
    std::cerr << accepted_ep_err.message() << std::endl;
    co_return;
  }
  std::cout << "Accepted BIND connection: " << ToString(*accepted_ep)
            << std::endl;
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
    tcp::socket bind_socket{co_await asio::this_coro::executor};
    // Send the BIND request and receive the incoming connection using libsocks.
    co_await Bind(bind_socket);
    for (size_t i = 0;; ++i) {
      co_await EchoOnce(bind_socket, i);
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