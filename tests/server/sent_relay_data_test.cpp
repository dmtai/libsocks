#include <gtest/gtest.h>
#include <server/sent_relay_data.hpp>
#include <socks5/common/asio.hpp>

namespace socks5::server {

TEST(SentRelayDataTest, SendAddsDataToVector) {
  const char* test_data{"test"};

  SentRelayData data;
  data.Send(test_data, sizeof(test_data));

  bool called{false};
  auto checker = [&](const RelayData& rd) -> BoolAwait {
    EXPECT_STREQ(rd.first, test_data);
    EXPECT_EQ(rd.second, sizeof(test_data));
    called = true;
    co_return true;
  };

  asio::io_context ctx;
  co_spawn(
      ctx,
      [&]() -> BoolAwait {
        co_await data.ForEach(checker);
        co_return true;
      },
      asio::detached);
  ctx.run();

  EXPECT_TRUE(called);
}

TEST(SentRelayDataTest, ClearRemovesAllData) {
  SentRelayData data;
  data.Send("test1", 5);
  data.Send("test2", 5);

  data.Clear();

  int call_count{};
  auto counter = [&](const RelayData&) -> BoolAwait {
    call_count++;
    co_return true;
  };

  asio::io_context ctx;
  co_spawn(
      ctx,
      [&]() -> BoolAwait {
        co_await data.ForEach(counter);
        co_return true;
      },
      asio::detached);
  ctx.run();

  EXPECT_EQ(call_count, 0);
}

TEST(SentRelayDataTest, ForEachReturnsTrueWhenEmpty) {
  SentRelayData data;
  asio::io_context ctx;
  bool result{false};

  co_spawn(
      ctx,
      [&]() -> VoidAwait {
        result = co_await data.ForEach(
            [](const RelayData&) -> BoolAwait { co_return true; });
        co_return;
      },
      asio::detached);
  ctx.run();

  EXPECT_TRUE(result);
}

TEST(SentRelayDataTest, ForEachProcessesAllItems) {
  SentRelayData data;
  std::vector<std::string> sent_data = {"test1", "test2", "test3"};
  for (const auto& item : sent_data) {
    data.Send(item.c_str(), item.size());
  }

  std::vector<std::string> received_data;
  auto collector = [&](const RelayData& rd) -> BoolAwait {
    received_data.emplace_back(rd.first, rd.second);
    co_return true;
  };

  asio::io_context ctx;
  co_spawn(
      ctx,
      [&]() -> BoolAwait {
        co_await data.ForEach(collector);
        co_return true;
      },
      asio::detached);
  ctx.run();

  ASSERT_EQ(received_data.size(), sent_data.size());
  for (size_t i = 0; i < sent_data.size(); ++i) {
    EXPECT_EQ(received_data[i], sent_data[i]);
  }
}

TEST(SentRelayDataTest, ForEachStopsOnFalseReturn) {
  SentRelayData data;
  data.Send("test1", 5);
  data.Send("test2", 5);
  data.Send("test3", 5);

  int processed_count{};
  auto stopper = [&](const RelayData&) -> BoolAwait {
    ++processed_count;
    co_return processed_count < 2;
  };

  asio::io_context ctx;
  co_spawn(
      ctx,
      [&]() -> BoolAwait {
        co_await data.ForEach(stopper);
        co_return true;
      },
      asio::detached);
  ctx.run();

  EXPECT_EQ(processed_count, 2);
}

TEST(SentRelayDataTest, ForEachHandlesNoexceptCallback) {
  SentRelayData data;
  data.Send("test", 4);

  auto noexcept_cb = [](const RelayData&) noexcept -> BoolAwait {
    co_return true;
  };

  asio::io_context ctx;
  bool result{true};
  co_spawn(
      ctx,
      [&]() -> BoolAwait {
        result = co_await data.ForEach(noexcept_cb);
        co_return true;
      },
      asio::detached);
  ctx.run();

  EXPECT_TRUE(result);
}

}  // namespace socks5::server