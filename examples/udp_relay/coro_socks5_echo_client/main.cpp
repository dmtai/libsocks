#include <boost/asio.hpp>
#include <socks5/client/client.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <iostream>
#include <chrono>
#include <socks5/common/address.hpp>
#include <array>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::string_view kProxyServerIP{"127.0.0.1"};
constexpr unsigned short kProxyServerPort{1080};

constexpr std::string_view kTargetEchoServerIP{"127.0.0.1"};
constexpr unsigned short kTargetEchoServerPort{5555};

constexpr size_t kTimeout{61440};
constexpr size_t kEchoBufSize{1024};

constexpr size_t kDatagramLen{65507};

constexpr std::string_view kEchoMessage{
    "Echo message for an example of using a client and "
    "server on the libsocks library."};

std::string_view ToString(const char* data, size_t len) noexcept {
  return std::string_view{data, len};
}

void Print(const char* data, size_t len, size_t n) {
  std::cout << n << ". Received: " << ToString(data, len) << std::endl;
}

asio::awaitable<socks5::client::UdpAssociateResultOrError> Connect(
    tcp::socket& socket) {
  tcp::endpoint proxy_server_ep{asio::ip::make_address_v4(kProxyServerIP),
                                kProxyServerPort};
  // Select an authentication method for the socks5 proxy.
  auto auth_options = socks5::auth::client::MakeAuthOptions();
  auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kNone>();

  // Connect asynchronously to the target server via the SOCKS5 proxy using
  // libsocks. The TCP socket must live while the interaction is going on via
  // UDP (see RFC 1928 https://datatracker.ietf.org/doc/html/rfc1928#section-6).
  co_return co_await socks5::client::AsyncUdpAssociate(socket, proxy_server_ep,
                                                       auth_options, kTimeout);
}

template <typename T>
asio::awaitable<std::error_code> EchoOnce(
    T& buf, socks5::client::UdpAssociateResult& udp_associate_res,
    const socks5::common::Address& target_server_addr, size_t n) {
  socks5::common::Address sender_addr;
  // Each call to AsyncReceiveFrom writes data to the beginning of the
  // DatagramBuffer.
  const auto [recv_err, recv_bytes] = co_await socks5::client::AsyncReceiveFrom(
      udp_associate_res.udp_socket, udp_associate_res.proxy_ep, sender_addr,
      buf, kTimeout);
  if (recv_err) {
    co_return recv_err;
  }
  Print(buf.Data(), buf.DataSize(), n);
  const auto [send_err, send_bytes] = co_await socks5::client::AsyncSendTo(
      udp_associate_res.udp_socket, udp_associate_res.proxy_ep,
      target_server_addr, buf.Data(), buf.DataSize(), kTimeout);
  if (send_err) {
    co_return send_err;
  }
  co_return std::error_code{};
}

asio::awaitable<void> Echo() noexcept {
  try {
    tcp::socket socket{co_await asio::this_coro::executor};
    auto [udp_associate_res_err, udp_associate_res] = co_await Connect(socket);
    if (udp_associate_res_err) {
      std::cerr << udp_associate_res_err.message() << std::endl;
      co_return;
    }

    socks5::common::Address target_server_addr{kTargetEchoServerIP,
                                               kTargetEchoServerPort};
    std::string aeaeae = udp_associate_res->proxy_ep.address().to_string();
    const auto [init_send_err, _] = co_await socks5::client::AsyncSendTo(
        udp_associate_res->udp_socket, udp_associate_res->proxy_ep,
        target_server_addr, kEchoMessage.data(), kEchoMessage.size(), kTimeout);
    if (init_send_err) {
      std::cerr << init_send_err.message() << std::endl;
      co_return;
    }

    std::array<char, kDatagramLen> underlying_buf;
    // Special buffer for receiving UDP datagrams from socks5 proxy. Each UDP
    // datagram from socks5 proxy contains a
    // header(https://datatracker.ietf.org/doc/html/rfc1928#section-7).
    // socks5::common::DatagramBuffer provides an interface to extract only the
    // body of a received message.
    auto buf = socks5::common::MakeDatagramBuffer(underlying_buf);
    for (size_t i = 0;; ++i) {
      co_await EchoOnce(buf, *udp_associate_res, target_server_addr, i);
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