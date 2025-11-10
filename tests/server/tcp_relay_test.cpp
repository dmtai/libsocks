#include <gtest/gtest.h>
#include <server/tcp_relay.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <test_utils/assert_macro.hpp>
#include <server/relay_data_processors.hpp>
#include <socks5/utils/watchdog.hpp>
#include <chrono>

namespace socks5::server {

namespace {

class TcpRelayTest : public testing::Test {
 protected:
  TcpRelayTest()
      : acceptor_{io_context_},
        client_socket_{io_context_},
        client_proxy_socket_{io_context_},
        server_socket_{io_context_},
        server_proxy_socket_{io_context_} {
    acceptor_.open(tcp::v4());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    acceptor_.listen();
  }

  void MakeSockets() {
    const auto server_endpoint = acceptor_.local_endpoint();
    client_socket_.async_connect(server_endpoint, [](auto) {});
    acceptor_.accept(client_proxy_socket_);

    server_socket_.async_connect(server_endpoint, [](auto) {});
    acceptor_.accept(server_proxy_socket_);
  }

  asio::io_context io_context_;
  tcp::acceptor acceptor_;
  tcp::socket client_socket_;
  tcp::socket client_proxy_socket_;
  tcp::socket server_socket_;
  tcp::socket server_proxy_socket_;
  common::Metrics metrics_;
};

void Read(std::shared_ptr<tcp::socket> from, std::shared_ptr<tcp::socket> to);

template <typename T>
void Write(T data, size_t size, std::shared_ptr<tcp::socket> from,
           std::shared_ptr<tcp::socket> to) {
  asio::async_write(
      *to, asio::buffer(data->data(), size),
      [from, to, data](const boost::system::error_code& err, size_t) {
        if (!err) {
          Read(from, to);
        }
      });
}

void Read(std::shared_ptr<tcp::socket> from, std::shared_ptr<tcp::socket> to) {
  auto buf = std::make_shared<std::array<char, 1024>>();
  from->async_read_some(
      asio::buffer(buf->data(), buf->size()),
      [from, to, data = buf](const boost::system::error_code& err,
                             size_t recv_bytes) {
        if (!err) {
          Write(data, recv_bytes, from, to);
        }
      });
}

void Relay(std::shared_ptr<tcp::socket> from, std::shared_ptr<tcp::socket> to) {
  Read(std::move(from), std::move(to));
}

void TestTcpRelayHandlerCb(asio::io_context& io_context,
                           socks5::tcp::socket client,
                           socks5::tcp::socket server, const Config& config,
                           common::Metrics& metrics) {
  auto client_socket_ptr = std::make_shared<tcp::socket>(std::move(client));
  auto server_socket_ptr = std::make_shared<tcp::socket>(std::move(server));
  Relay(client_socket_ptr, server_socket_ptr);
  Relay(server_socket_ptr, client_socket_ptr);
}

VoidAwait CoroRelay(tcp::socket& from, tcp::socket& to) {
  std::array<char, 1024> data;
  for (;;) {
    const auto recv_bytes =
        co_await from.async_read_some(asio::buffer(data), asio::use_awaitable);
    co_await asio::async_write(to, asio::buffer(data.data(), recv_bytes),
                               asio::use_awaitable);
  }
}

VoidAwait TestCoroTcpRelayHandlerCb(asio::io_context& io_context,
                                    socks5::tcp::socket client,
                                    socks5::tcp::socket server,
                                    const Config& config,
                                    common::Metrics& metrics) {
  co_await (CoroRelay(client, server) || CoroRelay(server, client));
}

}  // namespace

TEST_F(TcpRelayTest, DefaultTcpRelayHandlerBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       DefaultTcpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultTcpRelayDataProcessor()};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), data.size()),
                              asio::use_awaitable);
    EXPECT_EQ(data, buf);
    EXPECT_EQ(data.size(), metrics_.GetRecvBytesTotal());
    EXPECT_EQ(buf.size(), metrics_.GetSentBytesTotal());

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), data2.size()),
                              asio::use_awaitable);
    EXPECT_EQ(data2, buf2);
    EXPECT_EQ(data.size() + data2.size(), metrics_.GetRecvBytesTotal());
    EXPECT_EQ(buf.size() + buf2.size(), metrics_.GetSentBytesTotal());

    const std::vector<char> data3{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data3.data(), data3.size()),
                               asio::use_awaitable);
    std::vector<char> buf3(data3.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf3.data(), data3.size()),
                              asio::use_awaitable);
    EXPECT_EQ(data3, buf3);

    const std::vector<char> data4{'t', 'e', 's', 't', 'm', 's', 'g', '3'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data4.data(), data4.size()),
                               asio::use_awaitable);
    std::vector<char> buf4(data4.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf4.data(), data4.size()),
                              asio::use_awaitable);
    EXPECT_EQ(data4, buf4);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, DefaultTcpRelayHandlerTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    Config config{};
    config.tcp_relay_timeout = 1;
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       DefaultTcpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultTcpRelayDataProcessor()};

    auto tcp_relay_future =
        asio::co_spawn(io_context_, tcp_relay.Run(), asio::use_future);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);

    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), data.size()),
                              asio::use_awaitable);
    EXPECT_EQ(data, buf);

    const auto start = std::chrono::system_clock::now();
    co_await utils::Timeout(1100);
    tcp_relay_future.get();
    const auto finish = std::chrono::system_clock::now();
    const auto res =
        std::chrono::duration_cast<std::chrono::seconds>(finish - start);
    EXPECT_TRUE(res <= std::chrono::seconds{2});

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, TcpRelayHandlerWithDataProcessorBasicRelay1) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    std::string_view processed_testmsg1{"processed_testmsg1"};
    const auto client_to_server = [&](const tcp::endpoint& client,
                                      const tcp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg1"}));
        send(processed_testmsg1.data(), processed_testmsg1.size());
      };
    };

    std::string_view processed_testmsg2{"processed_testmsg2"};
    const auto server_to_client = [&](const tcp::endpoint& server,
                                      const tcp::endpoint& client) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg2"}));
        send(processed_testmsg2.data(), processed_testmsg2.size());
      };
    };

    TcpRelayDataProcessor tcp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TcpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       tcp_relay_data_processor};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(processed_testmsg1.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_EQ(processed_testmsg1, (std::string_view{buf.data(), buf.size()}));

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(processed_testmsg2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_EQ(processed_testmsg2, (std::string_view{buf2.data(), buf2.size()}));

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, TcpRelayHandlerWithDataProcessorBasicRelay2) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    bool client_to_server_processed{false};
    const auto client_to_server = [&](const tcp::endpoint& client,
                                      const tcp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        client_to_server_processed = true;
        send(data, size);
      };
    };

    bool server_to_client_processed{false};
    const auto server_to_client = [&](const tcp::endpoint& server,
                                      const tcp::endpoint& client) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        server_to_client_processed = true;
        send(data, size);
      };
    };

    TcpRelayDataProcessor tcp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TcpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       tcp_relay_data_processor};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(client_to_server_processed);
    EXPECT_EQ(buf, data);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm',
                                  's', 'g', '1', '2', '3'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(server_to_client_processed);
    EXPECT_EQ(buf2, data2);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest,
       TcpRelayHandlerWithDataProcessorMultipleDataTransmissions) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    bool client_to_server_processed{false};
    const auto client_to_server = [&](const tcp::endpoint& client,
                                      const tcp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        client_to_server_processed = true;
        send(data, size);
        send(data, size);
      };
    };

    bool server_to_client_processed{false};
    const auto server_to_client = [&](const tcp::endpoint& server,
                                      const tcp::endpoint& client) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        server_to_client_processed = true;
        send(data, size);
        send(data, size);
      };
    };

    TcpRelayDataProcessor tcp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TcpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       tcp_relay_data_processor};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(client_to_server_processed);
    EXPECT_EQ(buf, data);

    std::vector<char> buf2(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf2, data);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm',
                                  's', 'g', '1', '2', '3'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf3(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf3.data(), buf3.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(server_to_client_processed);
    EXPECT_EQ(buf3, data2);

    std::vector<char> buf4(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf4.data(), buf4.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf4, data2);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, TcpRelayHandlerWithDataProcessorTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    bool client_to_server_processed{false};
    const auto client_to_server = [&](const tcp::endpoint& client,
                                      const tcp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        client_to_server_processed = true;
        send(data, size);
      };
    };

    bool server_to_client_processed{false};
    const auto server_to_client = [&](const tcp::endpoint& server,
                                      const tcp::endpoint& client) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        server_to_client_processed = true;
        send(data, size);
      };
    };

    TcpRelayDataProcessor tcp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    config.tcp_relay_timeout = 1;
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TcpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       tcp_relay_data_processor};

    auto tcp_relay_future =
        asio::co_spawn(io_context_, tcp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(client_to_server_processed);
    EXPECT_EQ(buf, data);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm',
                                  's', 'g', '1', '2', '3'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_TRUE(server_to_client_processed);
    EXPECT_EQ(buf2, data2);

    co_await utils::Timeout(1100);
    auto res = tcp_relay_future.wait_for(std::chrono::milliseconds{1});
    EXPECT_EQ(res, std::future_status::ready);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, TcpRelayHandlerCbBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TestTcpRelayHandlerCb,
                       config,
                       metrics_,
                       MakeDefaultTcpRelayDataProcessor()};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf, data);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm',
                                  's', 'g', '1', '2', '3'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf2, data2);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(TcpRelayTest, CoroTcpRelayHandlerCbBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_proxy_connect{std::move(client_proxy_socket_),
                                            metrics_};
    net::TcpConnection server_proxy_connect{std::move(server_proxy_socket_),
                                            metrics_};

    Config config{};
    TcpRelay tcp_relay{io_context_,
                       std::move(client_proxy_connect),
                       std::move(server_proxy_connect),
                       TestCoroTcpRelayHandlerCb,
                       config,
                       metrics_,
                       MakeDefaultTcpRelayDataProcessor()};

    asio::co_spawn(io_context_, tcp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g'};
    co_await asio::async_write(client_socket_,
                               asio::buffer(data.data(), data.size()),
                               asio::use_awaitable);
    std::vector<char> buf(data.size());
    co_await asio::async_read(server_socket_,
                              asio::buffer(buf.data(), buf.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf, data);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm',
                                  's', 'g', '1', '2', '3'};
    co_await asio::async_write(server_socket_,
                               asio::buffer(data2.data(), data2.size()),
                               asio::use_awaitable);
    std::vector<char> buf2(data2.size());
    co_await asio::async_read(client_socket_,
                              asio::buffer(buf2.data(), buf2.size()),
                              asio::use_awaitable);
    EXPECT_EQ(buf2, data2);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server