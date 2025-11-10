#include <gtest/gtest.h>
#include <socks5/common/asio.hpp>
#include <socks5/common/address.hpp>
#include <socks5/common/datagram_buffer.hpp>
#include <common/socks5_datagram_io.hpp>
#include <socks5/error/error.hpp>

namespace socks5::common {

namespace {

constexpr uint16_t kTestPort{54321};
const udp::endpoint kTestEdnpoint{asio::ip::make_address("127.0.0.1"),
                                  kTestPort};

class Socks5DatagramIOTest : public testing::Test {
 protected:
  asio::io_context io_context;
};

}  // namespace

TEST_F(Socks5DatagramIOTest, MakeDatagramBuffsCorrectness) {
  Address addr{"example.com", 8080};
  const char* test_data{"hello"};
  const size_t data_size = sizeof(test_data) - 1;

  const auto buffs = MakeDatagramBuffs(addr, test_data, data_size);

  ASSERT_EQ(3, buffs.size());
  EXPECT_EQ(3, asio::buffer_size(buffs[0]));  // RSV + FRAG
  EXPECT_EQ(addr.Serialize().ReadableBytes(), asio::buffer_size(buffs[1]));
  EXPECT_EQ(data_size, asio::buffer_size(buffs[2]));
}

TEST_F(Socks5DatagramIOTest, SendAndReceiveDatagram) {
  bool test_completed{false};
  const std::string send_data{"Test payload"};
  std::string received_data;
  Address received_addr;

  auto server_coro = [&]() -> asio::awaitable<void> {
    udp::socket socket{co_await asio::this_coro::executor, udp::v4()};
    socket.bind(udp::endpoint{udp::v4(), kTestPort});

    char buffer[1024];
    udp::endpoint client_ep;
    const auto [err, len] = co_await socket.async_receive_from(
        asio::buffer(buffer), client_ep, use_nothrow_awaitable);
    EXPECT_FALSE(err);
    if (err) {
      co_return;
    }

    co_await socket.async_send_to(asio::buffer(buffer, len), client_ep,
                                  use_nothrow_awaitable);
  };

  auto client_coro = [&]() -> asio::awaitable<void> {
    udp::socket socket{co_await asio::this_coro::executor, udp::v4()};
    socket.bind(udp::endpoint{udp::v4(), 0});

    Address target_addr{"localhost", kTestPort};
    const auto [send_err, sent] = co_await SendTo(
        socket, kTestEdnpoint, target_addr, send_data.data(), send_data.size());
    EXPECT_FALSE(send_err) << "Send error: " << send_err.message();
    if (send_err) {
      co_return;
    }
    EXPECT_EQ(send_data.size() + target_addr.Serialize().ReadableBytes() + 3,
              sent);

    udp::endpoint proxy_ep;
    char raw_buffer[1024];
    DatagramBuffer dgbuf{raw_buffer, sizeof(raw_buffer)};
    Address sender_addr;
    const auto [recv_err, recv_len] =
        co_await ReceiveFrom(socket, proxy_ep, sender_addr, dgbuf);

    const auto domain = sender_addr.ToDomain();
    EXPECT_TRUE(domain);
    if (!domain) {
      co_return;
    }
    EXPECT_EQ(*domain, "localhost");
    EXPECT_EQ(sender_addr.Port(), kTestPort);

    EXPECT_FALSE(recv_err) << "Receive error: " << recv_err.message();
    if (recv_err) {
      co_return;
    }
    received_data.assign(dgbuf.Data(), dgbuf.DataSize());
    test_completed = true;
  };

  asio::co_spawn(io_context, server_coro, asio::detached);
  asio::co_spawn(io_context, client_coro, asio::detached);
  io_context.run_for(std::chrono::seconds{10});

  EXPECT_TRUE(test_completed);
  EXPECT_EQ(send_data, received_data);
}

TEST_F(Socks5DatagramIOTest, ReceiveInvalidDatagram) {
  bool test_completed{false};

  auto client_coro = [&]() -> asio::awaitable<void> {
    udp::socket socket{co_await asio::this_coro::executor, udp::v4()};
    socket.bind(udp::endpoint{udp::v4(), 0});

    const char bad_data[] = "\x00\x00";
    udp::endpoint client_ep{asio::ip::make_address("127.0.0.1"), kTestPort};
    co_await socket.async_send_to(asio::buffer(bad_data, sizeof(bad_data)),
                                  client_ep, use_nothrow_awaitable);
  };

  auto server_coro = [&]() -> asio::awaitable<void> {
    udp::socket socket{co_await asio::this_coro::executor, udp::v4()};
    socket.bind(udp::endpoint{udp::v4(), kTestPort});

    udp::endpoint proxy_ep;
    char raw_buffer[1024];
    DatagramBuffer dgbuf{raw_buffer, sizeof(raw_buffer)};
    Address sender_addr;
    const auto [recv_err, recv_len] =
        co_await ReceiveFrom(socket, proxy_ep, sender_addr, dgbuf);

    EXPECT_TRUE(recv_err);
    EXPECT_EQ(error::Error::kInvalidDatagram, recv_err);
    test_completed = true;
  };

  asio::co_spawn(io_context, server_coro, asio::detached);
  asio::co_spawn(io_context, client_coro, asio::detached);
  io_context.run_for(std::chrono::seconds{10});

  EXPECT_TRUE(test_completed);
}

}  // namespace socks5::common
