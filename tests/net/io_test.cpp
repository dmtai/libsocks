#include <gtest/gtest.h>
#include <net/utils.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/utils/buffer.hpp>
#include <net/io.hpp>
#include <chrono>

namespace socks5::net {

namespace {

class IoTest : public testing::Test {
 protected:
  void TearDown() override {
    io_context_.restart();
    io_context_.run_for(std::chrono::milliseconds{100});
  }

  asio::io_context io_context_;
};

asio::awaitable<std::tuple<tcp::socket, tcp::socket>> CreateConnectedPair() {
  auto executor = co_await asio::this_coro::executor;
  tcp::acceptor acceptor{executor,
                         tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0}};

  tcp::socket client{executor};
  co_await client.async_connect(acceptor.local_endpoint(),
                                use_nothrow_awaitable);

  auto [accept_err, server] =
      co_await acceptor.async_accept(use_nothrow_awaitable);
  if (accept_err) {
    throw std::system_error(accept_err);
  }

  co_return std::make_tuple(std::move(client), std::move(server));
}

}  // namespace

TEST_F(IoTest, SendTcpWithVerification) {
  co_spawn(
      io_context_,
      [&]() -> asio::awaitable<void> {
        auto [client, server] = co_await CreateConnectedPair();

        utils::StaticBuffer<10> send_buf;
        const char* test_data{"HelloTest"};
        const auto data_size = strlen(test_data);
        send_buf.Append(test_data, data_size);

        const auto send_err = co_await Send(client, send_buf);
        EXPECT_FALSE(send_err) << "Send error: " << send_err.message();

        utils::StaticBuffer<20> recv_buf;
        const auto read_err = co_await Read(server, recv_buf, data_size);

        EXPECT_FALSE(read_err) << "Read error: " << read_err.message();
        EXPECT_EQ(recv_buf.ReadableBytes(), data_size);

        const std::string received_data(recv_buf.BeginRead(),
                                        recv_buf.ReadableBytes());
        EXPECT_STREQ(received_data.c_str(), test_data);
      },
      asio::detached);

  io_context_.run();
}

TEST_F(IoTest, ReadTcpSuccess) {
  co_spawn(
      io_context_,
      [&]() -> asio::awaitable<void> {
        auto [client, server] = co_await CreateConnectedPair();
        utils::StaticBuffer<10> buf;

        const std::string test_data{"data"};
        co_await async_write(server, asio::buffer(test_data),
                             use_nothrow_awaitable);

        auto err = co_await Read(client, buf, test_data.size());
        EXPECT_FALSE(err);
        EXPECT_EQ(buf.ReadableBytes(), test_data.size());
        EXPECT_EQ((std::string{reinterpret_cast<const char*>(buf.BeginRead()),
                               buf.ReadableBytes()}),
                  test_data);
      },
      asio::detached);
  io_context_.run();
}

TEST_F(IoTest, ReadSomeTcpPartial) {
  co_spawn(
      io_context_,
      [&]() -> asio::awaitable<void> {
        auto [client, server] = co_await CreateConnectedPair();
        utils::StaticBuffer<10> buf;

        const std::string large_data(20, 'a');
        async_write(server, asio::buffer(large_data), asio::detached);

        auto err = co_await ReadSome(client, buf);
        EXPECT_FALSE(err);
        EXPECT_GT(buf.ReadableBytes(), 0);
        EXPECT_LT(buf.ReadableBytes(), large_data.size());
      },
      asio::detached);
  io_context_.run();
}

TEST_F(IoTest, ReadUdpWithEndpoint) {
  co_spawn(
      io_context_,
      [&]() -> asio::awaitable<void> {
        udp::socket sender{io_context_, udp::v4()};
        udp::socket receiver{io_context_, udp::v4()};
        receiver.bind(udp::endpoint{asio::ip::make_address("127.0.0.1"), 0});

        utils::StaticBuffer<20> buf;
        udp::endpoint sender_ep;
        const std::string test_data{"udp_test"};

        co_await sender.async_send_to(asio::buffer(test_data),
                                      receiver.local_endpoint(),
                                      use_nothrow_awaitable);

        const auto err = co_await Read(receiver, sender_ep, buf);
        EXPECT_FALSE(err);
        EXPECT_EQ(buf.ReadableBytes(), test_data.size());
        EXPECT_EQ((std::string_view{buf.BeginRead(), buf.ReadableBytes()}),
                  test_data.c_str());
        EXPECT_EQ(sender_ep.port(), sender.local_endpoint().port());
      },
      asio::detached);
  io_context_.run();
}

}  // namespace socks5::net
