#include <boost/asio.hpp>
#include <fmt/core.h>
#include <cstdlib>
#include <iostream>
#include <syncstream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr size_t kEchoBufSize{1024};
constexpr unsigned short kServerPort{5555};

std::string ToString(const udp::endpoint& ep) {
  return fmt::format("ip={} port={}", ep.address().to_string(), ep.port());
}

template <size_t Size>
std::string_view ToString(const std::array<char, Size> data,
                          size_t len = Size) noexcept {
  return std::string_view{data.data(), len};
}

template <size_t Size>
void Print(std::string_view addr, const std::array<char, Size> data,
           size_t len) {
  std::cout << "Received from: " << addr << ", msg: " << ToString(data, len)
            << std::endl;
}

class Server final : public std::enable_shared_from_this<Server> {
 public:
  Server(asio::io_context& io_context, unsigned short port)
      : socket_{io_context,
                udp::endpoint{asio::ip::make_address("127.0.0.1"), port}} {}

  void Receive() {
    socket_.async_receive_from(
        asio::buffer(data_), sender_ep_,
        [self = shared_from_this(), this](boost::system::error_code err,
                                          size_t recv_bytes) {
          if (!err && recv_bytes > 0) {
            Print(ToString(sender_ep_), data_, recv_bytes);
            Send(recv_bytes);
          } else {
            Receive();
          }
        });
  }

  void Send(size_t len) {
    socket_.async_send_to(
        boost::asio::buffer(data_, len), sender_ep_,
        [self = shared_from_this(), this](boost::system::error_code, size_t) {
          Receive();
        });
  }

 private:
  udp::socket socket_;
  udp::endpoint sender_ep_;
  std::array<char, kEchoBufSize> data_;
};

int main() {
  try {
    asio::io_context io_context;
    std::make_shared<Server>(io_context, kServerPort)->Receive();
    io_context.run();
  } catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    return 1;
  }
  return 0;
}