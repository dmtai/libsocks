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

class Client final : public std::enable_shared_from_this<Client> {
 public:
  Client(tcp::socket socket, tcp::endpoint proxy_server_ep,
         tcp::endpoint target_server_ep) noexcept
      : socket_{std::move(socket)},
        proxy_server_ep_{std::move(proxy_server_ep)},
        target_server_ep_{std::move(target_server_ep)},
        msg_num_{} {}

  void Run() {
    // Select an authentication method for the socks5 proxy.
    auto auth_options = socks5::auth::client::MakeAuthOptions();
    auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kNone>();

    // Connect asynchronously to the target server via the socks5 proxy using
    // libsocks.
    socks5::client::AsyncConnect(socket_, proxy_server_ep_,
                                 socks5::common::Address{target_server_ep_},
                                 auth_options, kTimeout,
                                 [self = shared_from_this(),
                                  this](const boost::system::error_code& err) {
                                   if (!err) {
                                     WriteInitialEchoMessage();
                                   }
                                 });
  }

 private:
  void WriteInitialEchoMessage() {
    asio::async_write(socket_,
                      asio::buffer(kEchoMessage.data(), kEchoMessage.size()),
                      [self = shared_from_this(), this](
                          const boost::system::error_code& err, size_t) {
                        if (!err) {
                          Read();
                        }
                      });
  }

  void Read() {
    socket_.async_read_some(
        asio::buffer(data_),
        [self = shared_from_this(), this](const boost::system::error_code& err,
                                          size_t recv_bytes) {
          if (!err) {
            Print(data_, recv_bytes, msg_num_++);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            Write(recv_bytes);
          }
        });
  }

  void Write(std::size_t length) {
    asio::async_write(socket_, asio::buffer(data_, length),
                      [self = shared_from_this(), this](
                          const boost::system::error_code& err, size_t) {
                        if (!err) {
                          Read();
                        }
                      });
  }

  tcp::socket socket_;
  tcp::endpoint proxy_server_ep_;
  tcp::endpoint target_server_ep_;
  size_t msg_num_;
  std::array<char, kEchoBufSize> data_;
};

int main() {
  try {
    asio::io_context io_context{1};
    tcp::socket socket{io_context};
    tcp::endpoint proxy_server_ep{asio::ip::make_address_v4(kProxyServerIP),
                                  kProxyServerPort};
    tcp::endpoint target_server_ep{
        asio::ip::make_address_v4(kTargetEchoServerIP), kTargetEchoServerPort};

    std::make_shared<Client>(std::move(socket), std::move(proxy_server_ep),
                             std::move(target_server_ep))
        ->Run();

    io_context.run();
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    return 1;
  }
}