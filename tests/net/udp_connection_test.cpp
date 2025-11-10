#include <gtest/gtest.h>
#include <net/udp_connection.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/utils/buffer.hpp>
#include <memory>
#include <string_view>
#include <chrono>

namespace socks5::net {

namespace {

class UdpConnectionTest : public testing::Test {
 protected:
  void SetUp() override {
    context_ = std::make_unique<asio::io_context>();
    metrics_ = std::make_shared<common::Metrics>();

    server_endpoint_ = udp::endpoint{asio::ip::make_address_v4("127.0.0.1"), 0};
    server_socket_ = std::make_unique<udp::socket>(*context_, server_endpoint_);
    server_endpoint_ = server_socket_->local_endpoint();

    client_socket_ = std::make_unique<udp::socket>(
        *context_, udp::endpoint{asio::ip::make_address_v4("127.0.0.1"), 0});

    server_conn_ =
        std::make_unique<UdpConnection>(std::move(*server_socket_), *metrics_);
  }

  void TearDown() override {
    if (client_socket_ && client_socket_->is_open()) {
      boost::system::error_code ec;
      client_socket_->close(ec);
    }
    if (server_conn_) {
      server_conn_->Stop();
    }
    context_->stop();
  }

  template <typename Coro>
  void RunTest(Coro coro) {
    std::exception_ptr eptr;
    bool done = false;
    auto handler = [&](std::exception_ptr e) {
      eptr = e;
      done = true;
    };
    co_spawn(*context_, std::move(coro), handler);
    context_->run();
    if (eptr) std::rethrow_exception(eptr);
    ASSERT_TRUE(done);
  }

  std::unique_ptr<asio::io_context> context_;
  std::shared_ptr<common::Metrics> metrics_;
  std::unique_ptr<UdpConnection> server_conn_;
  std::unique_ptr<udp::socket> client_socket_;
  std::unique_ptr<udp::socket> server_socket_;
  udp::endpoint server_endpoint_;
};

}  // namespace

TEST_F(UdpConnectionTest, SendSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Hello, UDP!"};
    const auto sent_before = metrics_->GetSentBytesTotal();

    const auto client_ep = client_socket_->local_endpoint();
    const auto err_opt = co_await server_conn_->Send(
        client_ep, test_data.data(), test_data.size());
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    const auto sent_after = metrics_->GetSentBytesTotal();
    EXPECT_EQ(sent_after - sent_before, test_data.size());

    std::array<char, 128> buf{};
    udp::endpoint sender_ep;
    boost::system::error_code ec;
    const auto bytes_read =
        client_socket_->receive_from(asio::buffer(buf), sender_ep, 0, ec);
    EXPECT_FALSE(ec);
    if (ec) {
      co_return;
    }

    EXPECT_EQ(bytes_read, test_data.size());
    EXPECT_EQ(std::string_view(buf.data(), bytes_read), test_data);
    EXPECT_EQ(sender_ep, server_endpoint_);
  });
}

TEST_F(UdpConnectionTest, ReadSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Test UDP packet"};

    co_await client_socket_->async_send_to(
        asio::buffer(test_data), server_endpoint_, asio::use_awaitable);

    utils::StaticBuffer<128> buf;
    const auto recv_before = metrics_->GetRecvBytesTotal();

    const auto [err_opt, sender_ep_opt] = co_await server_conn_->Read(buf);
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    EXPECT_TRUE(sender_ep_opt.has_value());
    if (!sender_ep_opt) {
      co_return;
    }

    const auto recv_after = metrics_->GetRecvBytesTotal();
    EXPECT_EQ(recv_after - recv_before, test_data.size());
    EXPECT_EQ(buf.ReadableBytes(), test_data.size());
    EXPECT_EQ(std::string_view(buf.BeginRead(), test_data.size()), test_data);
    EXPECT_EQ(sender_ep_opt->port(), client_socket_->local_endpoint().port());
  });
}

TEST_F(UdpConnectionTest, ReadTimeout) {
  RunTest([&]() -> asio::awaitable<void> {
    utils::StaticBuffer<128> buf;
    const auto [err_opt, sender_ep_opt] = co_await server_conn_->Read(buf, 1);
    EXPECT_TRUE(err_opt) << "Expected timeout error";
    if (!err_opt) {
      co_return;
    }
    EXPECT_EQ(err_opt->Msg(), "UDP socket receive timeout expired");
    EXPECT_FALSE(sender_ep_opt.has_value());
  });
}

TEST_F(UdpConnectionTest, CancelOperation) {
  bool read_completed = false;
  co_spawn(
      *context_,
      [&]() -> asio::awaitable<void> {
        utils::StaticBuffer<128> buf;
        const auto [err_opt, sender_ep_opt] = co_await server_conn_->Read(buf);
        EXPECT_TRUE(err_opt) << "Expected cancellation error";
        if (!err_opt) {
          co_return;
        }
        read_completed = true;
      },
      asio::detached);

  context_->run_for(std::chrono::milliseconds{10});

  const auto cancel_err = server_conn_->Cancel();
  ASSERT_FALSE(cancel_err) << "Cancel should not return error: "
                           << (cancel_err ? cancel_err->Msg() : "");

  context_->restart();
  context_->run_for(std::chrono::milliseconds{100});
  EXPECT_TRUE(read_completed);
}

TEST_F(UdpConnectionTest, SendViaBuffer) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Buffer test"};
    utils::StaticBuffer<64> buf;
    buf.Append(test_data.data(), test_data.size());

    const auto client_ep = client_socket_->local_endpoint();
    const auto err_opt = co_await server_conn_->Send(client_ep, buf);
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    std::array<char, 128> recv_buf{};
    udp::endpoint sender_ep;
    size_t bytes_read = co_await client_socket_->async_receive_from(
        asio::buffer(recv_buf), sender_ep, asio::use_awaitable);

    EXPECT_EQ(bytes_read, test_data.size());
    EXPECT_EQ(std::string_view(recv_buf.data(), bytes_read), test_data);
  });
}

}  // namespace socks5::net
