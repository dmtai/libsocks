#include <gtest/gtest.h>
#include <socks5/utils/watchdog.hpp>

namespace socks5::utils {

namespace {

class WatchdogTest : public ::testing::Test {
 protected:
  asio::io_context io_context_;
};

}  // namespace

TEST_F(WatchdogTest, RunTriggersCancellationOnTimeout) {
  Watchdog watchdog{io_context_.get_executor(), 1};
  watchdog.Update();

  bool cancellation_triggered = false;
  watchdog.Slot().assign([&](auto) { cancellation_triggered = true; });

  asio::co_spawn(
      io_context_, [&]() -> VoidAwait { co_await watchdog.Run(); },
      asio::detached);

  asio::steady_timer timer{io_context_, std::chrono::milliseconds{1100}};
  timer.async_wait([&](auto) { io_context_.stop(); });

  io_context_.run();
  EXPECT_TRUE(cancellation_triggered);
}

TEST_F(WatchdogTest, RunDoesNotTriggerCancellationIfUpdated) {
  Watchdog watchdog{io_context_.get_executor(), 2};
  bool cancellation_triggered = false;
  watchdog.Slot().assign([&](auto) { cancellation_triggered = true; });

  asio::co_spawn(
      io_context_, [&]() -> VoidAwait { co_await watchdog.Run(); },
      asio::detached);

  asio::steady_timer update_timer{io_context_, std::chrono::milliseconds{500}};
  update_timer.async_wait([&](auto) { watchdog.Update(); });

  asio::steady_timer stop_timer{io_context_, std::chrono::milliseconds{1100}};
  stop_timer.async_wait([&](auto) { io_context_.stop(); });

  io_context_.run();
  EXPECT_FALSE(cancellation_triggered);
}

TEST_F(WatchdogTest, Stop) {
  Watchdog watchdog{io_context_.get_executor(), 1};
  bool cancellation_triggered = false;
  watchdog.Slot().assign([&](auto) { cancellation_triggered = true; });
  watchdog.Update();

  asio::co_spawn(
      io_context_, [&]() -> VoidAwait { co_await watchdog.Run(); },
      asio::detached);

  asio::steady_timer stop_timer{io_context_, std::chrono::milliseconds{500}};
  stop_timer.async_wait([&](auto) { watchdog.Stop(); });

  io_context_.run();
  EXPECT_TRUE(cancellation_triggered);
}

TEST_F(WatchdogTest, ResetPreventsCancellation) {
  Watchdog watchdog{io_context_.get_executor(), 1};
  bool cancellation_triggered = false;
  watchdog.Slot().assign([&](auto) { cancellation_triggered = true; });

  watchdog.Update();
  watchdog.Reset();

  asio::co_spawn(
      io_context_, [&]() -> VoidAwait { co_await watchdog.Run(); },
      asio::detached);

  asio::steady_timer timer{io_context_, std::chrono::milliseconds{1100}};
  timer.async_wait([&](auto) { io_context_.stop(); });

  io_context_.run();
  EXPECT_FALSE(cancellation_triggered);
}

TEST_F(WatchdogTest, CustomTimeoutWorks) {
  Watchdog watchdog{io_context_.get_executor(), 2, 3};
  bool cancellation_triggered = false;
  watchdog.Slot().assign([&](auto) { cancellation_triggered = true; });
  watchdog.Update();

  asio::co_spawn(
      io_context_, [&]() -> VoidAwait { co_await watchdog.Run(); },
      asio::detached);

  asio::steady_timer timer{io_context_, std::chrono::milliseconds{1100}};
  timer.async_wait([&](auto) { io_context_.stop(); });

  io_context_.run();
  EXPECT_FALSE(cancellation_triggered);
}

}  // namespace socks5::utils