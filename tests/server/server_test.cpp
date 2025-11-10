#include <gtest/gtest.h>
#include <socks5/server/server.hpp>
#include <socks5/server/server_builder.hpp>
#include <utils/timeout.hpp>

namespace socks5::server {

namespace {

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{7779};

}  // namespace

TEST(ServerTest, Run) {
  auto builder = MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy = builder.Build();
  proxy.Run();

  asio::io_context io_context;
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    tcp::socket socket{io_context};
    tcp::endpoint endpoint{asio::ip::address::from_string(kListenerAddr),
                           kListenerPort};
    tcp::socket client_socket{io_context};
    co_await client_socket.async_connect(endpoint, asio::use_awaitable);

    io_context.stop();
    completed = true;
  };

  asio::co_spawn(io_context, main, asio::detached);
  io_context.run_for(std::chrono::seconds{5});

  proxy.Stop();
  proxy.Wait();
  EXPECT_TRUE(completed);
}

TEST(ServerTest, MultipleRun) {
  auto builder = MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy = builder.Build();

  for (int i = 0; i < 10; ++i) {
    proxy.Run();

    asio::io_context io_context;
    bool completed{false};
    auto main = [&]() -> asio::awaitable<void> {
      tcp::socket socket{io_context};
      tcp::endpoint endpoint{asio::ip::address::from_string(kListenerAddr),
                             kListenerPort};
      tcp::socket client_socket{io_context};
      co_await client_socket.async_connect(endpoint, asio::use_awaitable);

      io_context.stop();
      completed = true;
    };

    asio::co_spawn(io_context, main, asio::detached);
    io_context.run_for(std::chrono::seconds{5});

    proxy.Stop();
    proxy.Wait();
    EXPECT_TRUE(completed);
  }
}

TEST(ServerTest, MultipleRunAndDestroy) {
  for (int i = 0; i < 10; ++i) {
    auto builder = MakeServerBuilder(kListenerAddr, kListenerPort);
    auto proxy = builder.Build();

    proxy.Run();

    asio::io_context io_context;
    bool completed{false};
    auto main = [&]() -> asio::awaitable<void> {
      tcp::socket socket{io_context};
      tcp::endpoint endpoint{asio::ip::address::from_string(kListenerAddr),
                             kListenerPort};
      tcp::socket client_socket{io_context};
      co_await client_socket.async_connect(endpoint, asio::use_awaitable);

      io_context.stop();
      completed = true;
    };

    asio::co_spawn(io_context, main, asio::detached);
    io_context.run_for(std::chrono::seconds{5});

    proxy.Stop();
    proxy.Wait();
    EXPECT_TRUE(completed);
  }
}

TEST(ServerTest, Stopped) {
  auto builder = MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy = builder.Build();
  proxy.Run();

  asio::io_context io_context;
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    tcp::socket socket{io_context};
    tcp::endpoint endpoint{asio::ip::address::from_string(kListenerAddr),
                           kListenerPort};
    tcp::socket client_socket{io_context};
    co_await client_socket.async_connect(endpoint, asio::use_awaitable);

    io_context.stop();
    completed = true;
  };

  asio::co_spawn(io_context, main, asio::detached);
  io_context.run_for(std::chrono::seconds{5});

  EXPECT_FALSE(proxy.Stopped());
  proxy.Stop();
  EXPECT_TRUE(proxy.Stopped());
  proxy.Wait();
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server