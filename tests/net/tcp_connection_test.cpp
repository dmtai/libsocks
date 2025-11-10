#include <gtest/gtest.h>
#include <net/tcp_connection.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/utils/buffer.hpp>
#include <memory>
#include <string_view>

namespace socks5::net {

namespace {

class TcpConnectionTest : public testing::Test {
 protected:
  void SetUp() override {
    context_ = std::make_unique<asio::io_context>();
    metrics_ = std::make_shared<common::Metrics>();

    tcp::acceptor acceptor(
        *context_, tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    server_endpoint_ = acceptor.local_endpoint();

    tcp::socket client_socket(*context_);
    client_socket.connect(server_endpoint_);

    tcp::socket server_socket(*context_);
    acceptor.accept(server_socket);
    accepted_endpoint_ = server_socket.remote_endpoint();

    server_conn_ =
        std::make_unique<TcpConnection>(std::move(server_socket), *metrics_);
    client_socket_ = std::make_unique<tcp::socket>(std::move(client_socket));
  }

  void TearDown() override {
    if (client_socket_ && client_socket_->is_open()) {
      boost::system::error_code ec;
      client_socket_->shutdown(tcp::socket::shutdown_both, ec);
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
    bool done{false};
    auto handler = [&](std::exception_ptr e) {
      eptr = e;
      done = true;
    };
    co_spawn(*context_, std::move(coro), handler);
    context_->run();
    if (eptr) {
      std::rethrow_exception(eptr);
    }
    ASSERT_TRUE(done);
  }

  std::unique_ptr<asio::io_context> context_;
  std::shared_ptr<common::Metrics> metrics_;
  std::unique_ptr<TcpConnection> server_conn_;
  std::unique_ptr<tcp::socket> client_socket_;
  tcp::endpoint server_endpoint_;
  tcp::endpoint accepted_endpoint_;
};

}  // namespace

TEST_F(TcpConnectionTest, RemoteEndpointSuccess) {
  const auto [err_opt, ep_opt] = server_conn_->RemoteEndpoint();
  ASSERT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
  ASSERT_TRUE(ep_opt.has_value());
  EXPECT_EQ(ep_opt->port(), accepted_endpoint_.port());
}

TEST_F(TcpConnectionTest, LocalEndpointSuccess) {
  const auto [err_opt, ep_opt] = server_conn_->LocalEndpoint();
  ASSERT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
  ASSERT_TRUE(ep_opt.has_value());
  EXPECT_EQ(ep_opt->port(), server_endpoint_.port());
}

TEST_F(TcpConnectionTest, RemoteEndpointAfterClose) {
  server_conn_->Stop();
  const auto [err_opt, ep_opt] = server_conn_->RemoteEndpoint();
  ASSERT_TRUE(err_opt.has_value());
  EXPECT_FALSE(ep_opt.has_value());
}

TEST_F(TcpConnectionTest, SendSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Hello, world!"};
    const auto sent_before = metrics_->GetSentBytesTotal();

    const auto err_opt =
        co_await server_conn_->Send(test_data.data(), test_data.size());
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    const auto sent_after = metrics_->GetSentBytesTotal();
    EXPECT_EQ(sent_after - sent_before, test_data.size());

    std::array<char, 128> buf{};
    boost::system::error_code ec;
    const auto bytes_read = client_socket_->read_some(asio::buffer(buf), ec);
    EXPECT_FALSE(ec);
    if (ec) {
      co_return;
    }
    EXPECT_EQ(bytes_read, test_data.size());
    EXPECT_EQ(std::string_view(buf.data(), bytes_read), test_data);
  });
}

TEST_F(TcpConnectionTest, SendBufSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Hello, world!"};
    std::array<char, 128> underlying_buf;
    utils::Buffer test_buf{underlying_buf.data(), underlying_buf.size()};
    test_buf.Append(test_data.data(), test_data.size());

    const auto sent_before = metrics_->GetSentBytesTotal();

    const auto err_opt = co_await server_conn_->Send(test_buf);
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    const auto sent_after = metrics_->GetSentBytesTotal();
    EXPECT_EQ(sent_after - sent_before, test_data.size());

    std::array<char, 128> buf{};
    boost::system::error_code ec;
    const auto bytes_read = client_socket_->read_some(asio::buffer(buf), ec);
    EXPECT_FALSE(ec);
    if (ec) {
      co_return;
    }
    EXPECT_EQ(bytes_read, test_data.size());
    EXPECT_EQ((std::string_view{buf.data(), bytes_read}), test_data);
  });
}

TEST_F(TcpConnectionTest, SendTimeout) {
  RunTest([&]() -> asio::awaitable<void> {
    constexpr size_t large_size{10 * 1024 * 1024};  // 10MB
    const std::vector<char> large_data(large_size, 'x');

    const auto err_opt =
        co_await server_conn_->Send(large_data.data(), large_data.size(), 1);

    EXPECT_TRUE(err_opt) << "Expected timeout error";
    if (!err_opt) {
      co_return;
    }
    EXPECT_NE(err_opt->Msg().find("TCP socket write timeout expired"),
              std::string::npos);
  });
}

TEST_F(TcpConnectionTest, ReadSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Test read operation"};
    co_await asio::async_write(*client_socket_, asio::buffer(test_data),
                               asio::use_awaitable);

    utils::StaticBuffer<128> buf;
    const auto recv_before = metrics_->GetRecvBytesTotal();

    const auto err_opt = co_await server_conn_->Read(buf, test_data.size());
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    const auto recv_after = metrics_->GetRecvBytesTotal();
    EXPECT_EQ(recv_after - recv_before, test_data.size());
    EXPECT_EQ(buf.ReadableBytes(), test_data.size());
    EXPECT_EQ(std::string_view(buf.BeginRead(), test_data.size()), test_data);
  });
}

TEST_F(TcpConnectionTest, ReadSomeSuccess) {
  RunTest([&]() -> asio::awaitable<void> {
    const std::string test_data{"Partial read"};
    co_await async_write(*client_socket_, asio::buffer(test_data),
                         asio::use_awaitable);

    utils::StaticBuffer<128> buf;
    const auto err_opt = co_await server_conn_->ReadSome(buf);
    EXPECT_FALSE(err_opt) << "Error: " << (err_opt ? err_opt->Msg() : "");
    if (err_opt) {
      co_return;
    }

    EXPECT_GT(buf.ReadableBytes(), 0);

    const std::string_view received{buf.BeginRead(), buf.ReadableBytes()};
    EXPECT_EQ(received, test_data.substr(0, received.size()));
  });
}

TEST_F(TcpConnectionTest, ReadTimeout) {
  RunTest([&]() -> asio::awaitable<void> {
    utils::StaticBuffer<128> buf;
    const auto err_opt = co_await server_conn_->Read(buf, 5, 1);
    EXPECT_TRUE(err_opt) << "Expected timeout error";
    if (err_opt) {
      co_return;
    }
    EXPECT_EQ(err_opt->Msg(), "TCP socket read timeout expired");
  });
}

TEST_F(TcpConnectionTest, ReadErrorAfterClose) {
  RunTest([&]() -> asio::awaitable<void> {
    client_socket_->close();

    utils::StaticBuffer<128> buf;
    const auto err_opt = co_await server_conn_->Read(buf, 5);
    EXPECT_TRUE(err_opt) << "Expected error";
    if (!err_opt) {
      co_return;
    }

    EXPECT_NE(err_opt->Msg().find("Error reading from TCP socket"),
              std::string::npos);
  });
}

}  // namespace socks5::net
